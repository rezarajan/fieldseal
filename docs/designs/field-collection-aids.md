# Field Collection Aids and Survey Overlays

*   **Author:** Reza Rajan
*   **Status:** Proposed
*   **Date:** 2026-10-29

--------------------------------------------------------------------------------

## Overview

This design adds four things to the survey format and to every component that reads it. It has two parts.

**Part A: collection aids.** These come from collectors' feedback from the field.

1.  **Probes.** A question can list approved follow-ups, each with a stable id. Only the collector sees them. A collector uses one when an answer is vague, instead of making up their own wording. The question's `label` stays the exact words read aloud.
2.  **Broad answers.** A code in a code list can have a parent, for example `rice` under `cereals`. A question can allow an answer at the parent level when the interviewee can't be more specific. The recorded code shows how specific the answer was. Fieldseal never rolls answers up.
3.  **Verified entry.** A question can require `verify: retype` (a typed value is entered a second time without seeing the first) or `verify: read-back` (the collector reads the chosen answer back and the interviewee confirms it). A value that isn't verified can't be sealed.

**Part B: survey overlays.** These come from programmes that use standard surveys.

4.  **A modification policy, and overlays.**
    *   A *base* survey declares `modification: locked | extend | modify`. That declaration is part of the base's signed publication.
    *   An *overlay* names a published base by its address in the transparency log and adds its own questions where the policy allows.
    *   The compiler, the factory, the device and intake each recheck the overlay against the base, using one shared piece of code in the format core.
    *   Under `locked` or `extend`, an overlay may not add collection aids to the base's own questions.

The two parts are in one design because they share a single change to schema 1.0, one re-baseline of fingerprints and one migration of the examples. They are also linked by one rule: a standard survey must be able to forbid the aids that Part A adds.

**Input.** This design follows the brainstorm brief [`concepts_brief.field-collection-aids.md`](../../concepts_brief.field-collection-aids.md). The brief holds the reviewers' findings and the owner's decisions D1 to D19 of 2026-10-29. Decision ids (D*n*) and requirement ids (INS-, INT-, WIRE-, PUB-, COL-) refer to that brief and to `docs/reference/spec/`. The work is tracked in GitHub milestone M6, issues #25 to #45.

**Terms.**
*   A *probe* is an approved follow-up question shown only to the collector.
*   A *broad answer* is an answer recorded at a parent code.
*   A *base* is a published survey that others build on.
*   An *overlay* is a survey that names a base and adds to it.
*   An *extension point* is a place in a base where an overlay may add content.
*   *Inherited content* is the part of an overlay that comes from its base.

Where a term already has a meaning in the [glossary](../reference/glossary.md) (tenancy, fingerprint, content address, transparency log), that meaning holds.

## The Problem

**Collectors ask the same question in different ways.** They ask a question one way in one interview and another way in the next, so the answers vary for reasons that have nothing to do with the interviewee.
*   The format already has `label` (the question as asked, INS-150) and `guidance` (free-text notes for the collector, INS-151). Neither gives the collector approved words for a follow-up when an answer is vague, so collectors improvise.
*   The authoring dialect makes this worse. It fills a missing label in from the question's id. The example surveys use headings such as "Weight" as labels, so there is nothing to read aloud.

**Some answers are only known broadly.** An interviewee who can't say which grain they ate can often say "a cereal". Today a collector has two choices, and both lose information:
*   recording "don't know" loses what the interviewee did know;
*   picking a specific code records something the interviewee never said.

**Some typed values need to be confirmed.** A mistyped id, phone number or amount passes every range check and can't be caught afterwards.
*   The example survey asks the collector in free text to "weigh twice; the two readings must match", but nothing enforces it.
*   `measure-twice` exists, but it compares two visible readings within a tolerance. That doesn't catch a keying error that is made twice.

**Standard surveys can't protect themselves.** Some standard questionnaires state rules on the form itself:
*   read every question exactly as written;
*   add no probing questions;
*   add or remove no items;
*   put any extra questions at the end.

A local port of one such questionnaire (never committed, because its licence forbids derivatives) showed that Fieldseal holds the questions without trouble but can't express or enforce any of those rules.
*   `derived-from` (INS-112) is only a citation; nothing checks a derived survey against its source.
*   Programmes that need a standard survey plus a few questions of their own must therefore copy and edit the whole survey. Nothing then shows whether the standard's questions still mean the same thing, so data from different programmes can't safely be pooled.
*   Part A makes this more urgent. Once probes, broad answers and verification exist, anyone could add them to a standard's questions and change what its answers mean.

## Goals

*   **One wording.** In interviewer surveys, the collector reads `label` as written and sees the question's approved probes. A probe is available in every language the survey declares; a missing or stale probe translation fails `survey check` (D13).
*   **Broad answers are real codes.** A question that allows broad answers records the parent code. Rules can test "this answer or anything under it" with `within()`. The data contract and codebook carry each code's parent, so an analyst can see that an answer is broad without Fieldseal deriving anything.
*   **Verified entry that can't be skipped.**
    *   A `verify` question can't be sealed until it is verified. Nonresponse is exempt.
    *   The first entry is never written to the record, not even on pause.
    *   Mismatches, pauses and resurveys each have a defined outcome (D9).
    *   Intake re-checks this rule when it replays records.
*   **Probe use is recorded where it is useful.** Tapping a probe records its id in a `<path>.probes` item next to the answer, with no change to the wire format (D3, D5). The contract labels it as self-reported by the collector.
*   **A policy that is checked everywhere.** A base declares `locked`, `extend` (with named extension points, D14) or `modify`. The same core code checks an overlay in `survey check`, at the factory's bundle build, at device import and at intake. A failure is refused with a reason, never accepted with a warning.
*   **The lock covers aids.** Under `locked` or `extend`, an overlay can't add probes, broad answers or verification to the base's questions; it may use them on its own questions.
*   **Approved publishers.** A base may list the keys allowed to translate it (`translators:`) and to publish overlays of it (`overlay-publishers:`) (D17, D19). With no translator list, only the base's own publisher may translate a `locked` or `extend` base.
*   **Comparable data.** Every column of an overlay's data contract, codebook and export is marked `inherited` (with the base's address) or `added`. Inherited columns of one base can then be pooled across overlays with one filter (D16).
*   **Every UI enforces every new constraint.** The shared constraint corpus (`tests/constraints/`) has cases for each new constraint. `CheckCompatibility` rejects a runtime that lacks one (INS-254).
*   **No version migration.** Schema 1.0 is changed in place before v0.1.0 (D1). Fingerprints and example addresses are re-baselined once, deliberately, in one commit that can be reverted.

## Non-Goals

*   A new major schema version or support for running two majors side by side. That is a follow-up after the release (#45).
*   A separate read-aloud field next to `label`. It is deferred until `administration: both` needs it (D2).
*   Fieldseal rolling answers up, scoring them or adding a precision column (INS-226, INS-228, INT-092). Analysts do that downstream.
*   Probe text typed by the collector, or probes that aren't on the approved list.
*   The device reading answers aloud by text-to-speech.
*   Overlays of overlays. One level only; a `chainable` flag may come later (D15).
*   Enforcing a licence. The policy is a technical control, and the licence id only informs a lint warning (D18).
*   Merging the data of different overlays into one table at intake (D16).
*   The native Android UI, which doesn't exist yet. The bindings and `ControlCatalogue` expose everything it will need (D13).
*   Recording, for each capture, whether it was administered by a collector or by the subject. Until that exists, probes and read-back are refused on `administration: both` surveys (D11).

## Open Questions

*   **Which broad answers do the collectors mean? (D7)** The field complaint may be about a choice answer ("which grain?") or about a repeated block per food ("how often do you eat rice?" when the interviewee only knows "cereals").
    *   Hierarchical code lists solve the first.
    *   The second needs a category-level instance of a repeat, which this design doesn't include.
    *   This must be confirmed with the collectors before ADR 0042 is accepted. If it is the second case, the design gains a section.

## Critical User Journeys (CUJs)

### CUJ 1: A collector uses an approved probe

*   **Given:** an interviewer survey whose question `meals.breakfast` lists two probes, translated into every language the survey declares, and loaded on a registered device.
*   **When:** the collector reads the label, gets a vague answer and taps a probe chip, then records the answer and seals.
*   **Then:**
    *   the probe's text was shown in the interview's language;
    *   the sealed record holds the answer and `meals.breakfast.probes = [<probe id>]`;
    *   after upload, the results export carries the probe id in its own row, and the codebook gives the probe texts and marks them self-reported.

### CUJ 2: A collector records a broad answer

*   **Given:** a question with `broad-answer: allowed` over a code list where `rice` and `maize` have the parent `cereals`, and a follow-up question shown when `within(grain, cereals)`.
*   **When:** the interviewee can only say "a cereal", and the collector uses the broad-answer action.
*   **Then:**
    *   the record holds `cereals`, and the follow-up is shown;
    *   a rule written `eq: [grain, rice]` doesn't fire, and `survey check` warned the author about that rule;
    *   the codebook lists `cereals` as the parent of `rice` and `maize`.

### CUJ 3: A collector verifies a household id

*   **Given:** a text question with `verify: retype`.
*   **When:** the collector types the id, then types it again without seeing the first entry, and the two entries differ.
*   **Then:**
    *   the device says the entries don't match, writes neither, and keeps any earlier value;
    *   after a second mismatch it offers the declared nonresponse actions or a reason;
    *   the capture can't be sealed until the entries match or nonresponse is chosen;
    *   pasting into the second field is refused.

### CUJ 4: A programme extends a locked standard

*   **Given:** a base survey published with `modification: extend` and `extension-points: [end]`, and a programme's overlay that names the base's address and adds two questions at `end`.
*   **When:** the programme runs `fieldseal survey check`, publishes the overlay, and a device receives a bundle built from it.
*   **Then:**
    *   `survey check`, the factory, the device and intake each recompute the inherited content from the base found by address, and accept;
    *   the intake contract marks the base's columns `inherited` (with the base's address) and the two new columns `added`.

### CUJ 5: An overlay that breaks the policy is refused everywhere

*   **Given:** an overlay of the same base that changes one base question's label, adds a probe to a base question, or adds a question outside `end`.
*   **When:** the author runs `survey check`, or the overlay is forced past it to the factory, a device or intake.
*   **Then:**
    *   each of the four verifiers refuses it with the same finding, naming the rule broken and the path;
    *   no bundle is built and no record of it lands.

### CUJ 6: A standard publisher approves a translator

*   **Given:** a `locked` base that lists a certified translation agency's key under `translators:`.
*   **When:** the agency publishes a translation of the base signed with that key, and someone else publishes a translation signed with a key that isn't listed.
*   **Then:** verifiers accept the agency's translation and refuse the other with a finding that names the missing approval.

## Technical Plan (Architecture)

Section numbers below (§1 to §9) are referred to by the Detailed Implementation Plan.

### §1. Where the work sits

Everything new about the survey format lives in the format core: the `fieldseal-instrument` context, which is pure, with no I/O (ADR 0028). Everything new about who may sign what lives in `fieldseal-publishing`. Adapters and apps only call these, so the CLI, the factory, the device runtime (wasm and, later, UniFFI) and intake run one implementation of each check.

```text
                  survey folder (instrument.yaml, i18n/*.po, layouts/, overlay.yaml)
                                  │  compact dialect (adapters/authoring)
                                  ▼
 ┌────────────────────── fieldseal-instrument (format core, pure) ──────────────────────┐
 │ model: probes · code parent · broad-answer · verify · modification · extension slots │
 │ compile → render plan (probe chips, broad-answer action, verify step)                 │
 │ evaluate: within() · verify gate at seal · .probes sibling                            │
 │ overlay::check(base, overlay) → findings        (§6: content rules, aids lock)        │
 │ ControlCatalogue / CheckCompatibility list constraint kinds (INS-254)                 │
 └──────────────────────────────────────────────────────────────────────────────────────┘
                                  │
 ┌──────────── fieldseal-publishing ────────────┐
 │ overlay::authorise(base pub, overlay pub)    │  (§7: base in log, signer allow-lists,
 │   → findings                                 │   policy downgrade)
 └──────────────────────────────────────────────┘
        │                 │                     │                     │
   CLI survey check   factory bundle build   device bundle import   intake InstrumentSource
   (adapters/authoring, (apps/factory,        (contexts/collection  (adapters/file
    apps/cli)            contexts/distribution) via bindings/wasm)    instruments.rs)
```

### §2. Schema 1.0, amended in place

All new keys are additions to schema 1.0 before v0.1.0 (D1). Nothing is renamed and no existing key changes meaning.
*   Every new canonical field is emitted only when it is used, and the schema range stays `^1.0` (`compact.rs`), so an instrument that uses none of them keeps its canonical bytes and its fingerprint (INS-200).
*   The examples' fingerprints change because they are migrated to use the new keys (§9). The goldens and the migration gate are re-baselined once, in one commit.
*   The Detailed Implementation Plan's first step confirms this with a test: the canonical bytes of an unmigrated instrument are unchanged.

The compact dialect (ADR 0040) gains these keys. The canonical (expanded) form gains the matching fields, in `camelCase` like the rest.

| Compact key | Where | Canonical field | Meaning |
|---|---|---|---|
| `probes: {<id>: <text>, …}` | question | `probes: [{id, text}]` | Approved follow-ups, collector-only (§3) |
| `parent: <code>` | code-list item | `parent` | The item's parent code (§4) |
| `broad-answer: allowed` | choice question | `broadAnswer: "allowed"` | The question accepts a parent code (§4) |
| `{under: [path, code]}` | rule | `within(path, code)` | True when the answer is the code or any descendant (§4) |
| `verify: retype \| read-back` | question | `verify` | The value must be verified before seal (§5) |
| `modification: locked \| extend \| modify` | survey | `spec.modification` | The base's policy (§6) |
| `extension-points: [end, <name>…]` | survey | `spec.extensionPoints` | Where an overlay may add content; `end` is implicit (§6) |
| `extension-point: <name>` | section | an element marker | Places a named point after this section (§6) |
| `overlay-publishers: [<key id>…]` | survey | `spec.overlayPublishers` | Who may publish overlays of this base (§7) |
| `translators: [<key id>…]` | survey | `spec.translators` | Who may publish translations of this base (§7) |
| `base: {name, version, address}` | overlay | `spec.base` | The base this overlay extends (§6) |
| `extend: {<point>: [elements…]}` | overlay | `spec.extensions` | What the overlay adds, by extension point (§6) |

The compact dialect gets a normative reference page, `docs/reference/survey-dialect.md`, that lists every key, including the existing ones. It is generated from the schema tables in `crates/kernel/src/schema.rs` where they exist, so it cannot drift from the decoder.

`probes`, `probe`, `extensions` and `base` become reserved path segments (INS-012), like `help` and `guidance`, so a question can't be named after them.

### §3. Probes

**Model and compile.**
*   A question may carry `probes: [{id, text}]`.
    *   `id` is a stable slug, unique within the question and pinned like a code (INS-136).
    *   `text` is localised text, with the same variables as `label` (INS-047, INS-084), so a probe inside a repeat can name the repeated item.
*   Probes are collector-only. They follow `guidance`'s path through the model, the decoder, the render plan and the self-mode stripping. Probes are refused on `self` surveys, and on `both` surveys until the administration mode is recorded per capture (D11).
*   The lint that fires when an interviewer question has no `guidance` also suggests probes. It is advisory.

**Translation.**
*   Each probe's `.po` context is `instrument/<path>.probes.<id>`.
*   A probe that is missing or stale in any declared language is an error, not an English fallback (D13). This tightens INS-260 for probes only.

**Runtime.**
*   The render plan gives each question a list of probe chips.
*   Tapping a chip shows the probe's text large enough to read aloud, and adds its id to a synthesised sibling item `<path>.probes` (data type `codes`; the probe ids are its code list).
*   The sibling follows the fold rule of `.unit`: setting the value without touching probes keeps the probe set, and clearing the value clears it.

**Suffix handling first.** `.unit` is hard-coded in at least seven places, and `.other` in several more. Before `.probes` is added, these become one `annotation` module in the format core. It names each suffix, its data type and its fold rule. `QuestionOrigin::Annotation(kind)` replaces the special cases. The bug where a retracted item keeps its `.unit` sibling, if confirmed, is fixed there.

**Landing.** `.probes` lands as its own observation row with the probe ids, the way `.unit` does. No new export column is needed. The codebook lists the probe texts in every language and marks the item `self-reported: true`. The data contract says so in plain words (D4, D5).

### §4. Broad answers

**Model.**
*   A code-list item may name a `parent` code from the same list. The list stays flat; the hierarchy is a forest at most 8 deep, as for concepts (INS-242).
*   A code with children is a *parent code*. A choice question accepts a parent code only if it declares `broad-answer: allowed`. Otherwise the parent codes are headings that can't be selected.
*   `concept` stays descriptive, as before. `survey check` warns when a code's `parent` and its concept's parent disagree.

**Rules over the hierarchy (D8).**
*   `eq`, `ne` and `in` stay exact, so existing records replay identically (INT-012).
*   The new rule function `within(path, code)` is true when the answer is the code or any descendant of it. In multi-choice it is true if any selected code is.
*   `survey check` warns when `eq` or `in` compares with a code that has a selectable ancestor in a `broad-answer` question, because a broad answer won't match.

**Interactions** (each is a compile error unless stated):
*   **Multi-choice:** selecting a code and its ancestor together is refused at entry, like an exclusive option (INS-133). `max` counts selected codes.
*   `exclusive` on a parent code.
*   `value` on a parent code (INS-132).
*   Hierarchy on a `scale` or ordered list (INS-135).
*   A repeat over a list with parents.
*   `other` stays one per list, attached to the list, not to a parent.

**Entry (D6).**
*   The collector sees the leaves grouped under their parent headings.
*   A broad answer is a secondary action next to the control ("Only knows: Cereals"), not a peer option. It is shown after the question's probes, so the collector has tried the approved follow-ups before falling back.

**What a broad answer is.** It is a value, not a nonresponse. `dont-know` stays available and records a different fact.
*   Nothing is stored about how specific the answer is (D4). The recorded code already shows it.
*   The data contract (`ContractCode.parent`) and the codebook (`parent_code`, `is_leaf`) carry the parent chain as unevaluated metadata (INS-228). Analysts roll answers up downstream.

### §5. Verified entry

**Kinds.**
*   `verify: retype` is for typed `number`, `money`, `text` and `date` questions.
*   `verify: read-back` is for `choice` and `choices` questions in interviewer administration.
*   Each is refused elsewhere: on `measurement-pair`, `stepper` and `roster` items, and `read-back` on `self` surveys.
*   An optional `when:` condition limits verification to some answers, for example amounts above a threshold.

**Retype lifecycle (D9).**
*   The first entry is UI state only. It is never written to the pending record, not even on pause.
*   The second entry is typed without the first visible. Paste is refused, and autofill and IME suggestions are off.
*   The two entries are compared after locale normalisation and NFC (INS-088, WIRE-004).
*   **On a match,** the value is written.
*   **On a mismatch,** both entries are discarded and the earlier value, if any, is kept (INS-253). After a second mismatch, the device offers the question's declared nonresponse actions or a typed reason.

**Read-back lifecycle (D10).**
*   The device shows the chosen answer with "Read this back to the respondent".
*   The collector confirms with one tap. It is never hold-to-confirm, which is reserved for irreversible actions (INS-024).
*   The guidance says that the collector, not the device, speaks.

**The gate.**
*   `Capture::readiness()` reports a verify item set or changed in this capture and not yet verified as a value problem (INS-164). The capture can't be sealed until it is resolved.
*   Values carried over unchanged in a resurvey or correction need no new verification.
*   Nonresponse needs none.
*   Intake re-checks the gate when it replays records (INT-012). Because the gate can't be bypassed, every sealed value of a verify item is verified by construction, so nothing extra is stored (D4).

**Compatibility.**
*   `ControlCatalogue` gains the list of constraint kinds a runtime enforces. `CheckCompatibility` refuses an instrument that uses a kind the runtime doesn't list (INS-254, today unimplemented, #29).
*   This is what stops an older web build from showing a verify question without verifying it.

**Accessibility.**
*   The second field has its own label ("Type it again").
*   A mismatch is announced in a live region (WCAG 4.1.3).
*   The question says "entered twice" before the first entry (WEB-186).
*   Blind re-entry is documented as the "essential" exception to WCAG 2.2 SC 3.3.7 (Redundant Entry).

### §6. Overlays and the modification policy

**The base declares the policy.**
*   `spec.modification` is `locked`, `extend` or `modify`. If it is absent, the base is `modify`, which matches today's behaviour (INS-112 citation only).
*   `extend` names its extension points. `end` always exists; a named point sits after a top-level section (D14).
*   The policy is part of the base's canonical bytes, so it is covered by the base's content address and its publisher signatures (PUB-021, PUB-040).

**The overlay is published resolved.**
*   An overlay folder holds `overlay.yaml` instead of `instrument.yaml`. It has `base: {name, version, address}`, `extend: {<point>: [elements…]}` and its own metadata (name, version, title, publisher), plus optional `i18n/*.po` for languages it adds.
*   `survey check` resolves it into one complete canonical instrument: the base's content, the added elements placed in `spec.extensions` slots at their points, the overlay's metadata, and `spec.base`.
*   The resolved instrument is what is published, bundled and run. Runtimes evaluate it like any other instrument, so evaluation needs no overlay logic. Only verification does.

**The check is one comparison: `overlay::check(base, overlay)`.** It lives in `fieldseal-instrument`, is pure, and returns findings.
1.  `base.spec.modification` must not be `modify`; if it is, the check passes, because there is nothing to enforce.
2.  The overlay must have no top-level content outside the base's content and its `spec.extensions` slots, and each slot must name an extension point the base declares (`end`, or one of `extensionPoints` under `extend`; none under `locked`).
3.  **Projection.** Take the overlay's canonical form and remove:
    *   the `spec.extensions` slots;
    *   the overlay's own metadata fields (name, version, title, description, publisher, copyright, `base`);
    *   every language the base does not declare.
4.  The projection's canonical bytes must equal the base's canonical bytes, minus the base's own metadata fields. A difference is reported with the first differing path.
    *   **What this one comparison catches:** changed wording, removed or reordered items, changed code lists or rules, and probes, `broad-answer` or `verify` added to a base question. That last case is the D-decided rule that a lock covers aids, and it needs no rule of its own.
5.  **Rules added by the overlay may read base answers but may not change them.** An added check may not `skip`, `set` or hide a base path, and an added element's `if` may only gate added elements. This keeps every base question's applicability, and so its data, unchanged (INS-142).
6.  **Added paths live under the overlay's slot,** so they never shadow a base path, and the base's data contract columns are unchanged.
7.  **A language-only overlay is a translation (CUJ 6).** It has no `extend` and adds only languages. Its approval is checked in §7.

Under `locked` only step 7 applies. Under `extend`, steps 1 to 7 all apply.

**Base withdrawn.** A withdrawn base (PUB §5.9) does not invalidate existing overlays or their landed data. The factory will not build a new bundle from an overlay whose base is withdrawn.

### §7. Who may publish, and policy downgrade

**`overlay::authorise(base_publication, overlay_publication)`** lives in `fieldseal-publishing`. It runs after the content check.
*   The base's publication must be in the transparency log, verified against the publisher threshold (PUB-040). Its address must equal `spec.base.address`.
*   **Signer allow-lists.**
    *   If the base lists `overlayPublishers`, at least one signature on an overlay that has `extensions` must come from a listed key.
    *   If the base lists `translators`, a language-only overlay must be signed by a listed key.
    *   With no `translators` list, only the base's own publisher keys may sign a language-only overlay of a `locked` or `extend` base (D17).
    *   With no `overlayPublishers` list, any publisher trusted by the trust bundle may publish an overlay (D19).
*   **Downgrade.** A base whose policy is weaker than that of the highest earlier version of the same name in the artefact registry (the log holds no names, PUB-104) is refused, unless it declares `relaxes: <earlier address>`.
    *   The order from strongest to weakest is `locked`, then `extend`, then `modify`.
    *   Removing an extension point is tightening; adding one is relaxing.
    *   The marker makes a relaxation explicit and visible in review (PUB-011). Tightening needs no marker.

### §8. The four verifiers

Each verifier runs `overlay::check`, then `overlay::authorise`, and refuses on any finding. All four use the same finding codes.

| Verifier | Where the base comes from | On failure |
|---|---|---|
| `fieldseal survey check` | The local registry or a `--base <file>`; the CLI checks the bytes against the address | Error findings; exit 1 |
| Factory bundle build | The artefact registry, by address | `bundle-failed` with the finding; no bundle; the reconciler event names it |
| Device bundle import | The bundle: it carries the base's publication next to every overlay's publication (`BundleContent.bases`) | The import is refused, and the device keeps its earlier bundle |
| Intake (`InstrumentSource`) | The artefact registry, by address | The instrument is "not verified", and its records are held with a new reason, INT-093 (overlay does not verify against its base; INT-013 is the duplicate rule), not the generic "not published" |

`BundleContent` gains `bases: Vec<Publication>`: the bases of the overlays it carries, for verification only. A base that is not itself assigned is never offered for capture.

### §9. Data, examples and migration

**Lineage at intake (D16).**
*   Each overlay lands as its own instrument (INT-070).
*   The data contract and the codebook give every column a `lineage` of `inherited` or `added`, and a `base_address` on inherited columns.
*   The export has no `instruments.csv`. The `instruments` entries of `manifest.json` gain `base_address`, and `codebook.csv` gains `lineage` and `base_address` columns. A query that pools a base's columns across overlays joins the results to the codebook and filters on them.
*   `LONG_COLUMNS` is unchanged. Lineage is a join to the contract, the codebook or the manifest, so the snapshot reader needs no migration.
*   `EXPORT_SCHEMA_VERSION` becomes 1.1.0, for the new contract and codebook columns (INT-085).

**Examples.**
*   `school-meals-baseline` gains `short-label`s and real read-aloud labels, probes on two questions, a hierarchical food list with `broad-answer` on one question, and `verify: retype` on the pupil id.
*   `household-water-access` gains a `parent` grouping of water sources, which today's `concept` classification already suggests.
*   A new, original example, `examples/surveys/diet-recall-standard`, is a `locked`-then-`extend` standard survey: a yes/no list in groups with an introduction. Next to it is an overlay, `examples/surveys/diet-recall-programme`, that adds two questions at `end`. These are written for the project, never copied from a real questionnaire.
*   The conformance fixtures under `crates/contexts/instrument/tests/overlay/` hold accepted and refused overlays for every rule in §6 and §7.

**Re-baseline.**
*   The goldens (`crates/apps/e2e/tests/golden/expanded/`, `crates/contexts/instrument/tests/golden/*.plan`) and the migration gate's recorded addresses are regenerated in one commit, after the model changes and before the example migration.
*   The commit message lists the old and new addresses. It is revertible on its own.

**Rollout.** Nothing is released, so there is no device or data to migrate. A runbook (`docs/how-to/amend-schema-1.0.md`) says what one must still do:
*   rebuild the CLI, the factory and the web device from the same commit, because builds from different commits disagree on fingerprints;
*   run `just purge` on any local stack;
*   republish the examples.

## Alternatives Considered

Grouped by the decision each one competed with. The brief records the reviewers' full reasoning; this section states why each option lost.

### Versioning

#### Alternative A1: A new major schema version
*   **Pros:** old and new meanings can't mix; every runtime has to re-certify.
*   **Cons:** a runtime runs one major only (INS-092), so every registered device is stranded until it re-registers or rolls its key (DIS-012, REG-091). It also needs a new intake finding for unsupported majors and two publications of each survey for rollback.
*   **Reason for rejection:** nothing is released, schema 1.0 has been amended in place before (`hint` to `data`, WIRE-212), and the changes are additive (INS-090) (D1). Multi-major support is still needed eventually, so it is tracked for after the release (#45).

#### Alternative A2: Ship as schema 1.1
*   **Pros:** the versioning rule as written (INS-090); older runtimes refuse 1.1 surveys cleanly.
*   **Cons:** before the first release it adds a version that no deployed runtime will ever see.
*   **Reason for rejection:** amending 1.0 has the same effect with less to maintain (D1).

### Probes and wording

#### Alternative B1: A separate `script` (read-aloud) field next to `label`
*   **Pros:** one text for a respondent's screen and another for the collector's voice.
*   **Cons:** two texts would both claim to be "the question as asked" (INS-150). It doubles translation and review, and scripts would need their own solution for repeats.
*   **Reason for rejection:** for interviewer surveys `label` already is the script (D2). The field is deferred until `administration: both` needs it.

#### Alternative B2: Better display of `guidance`, no schema change
*   **Pros:** cheapest; nothing new to translate.
*   **Cons:** free text doesn't stop the follow-up wording drifting, and nothing records which follow-up was used.
*   **Reason for rejection:** it doesn't address the field complaint. The authoring fixes it implies (`short-label`, no labels filled from ids, a heading lint) are kept anyway (#26).

#### Alternative B3: Store probe use in a typed `annotations` map in the record
*   **Pros:** analysts get process data apart from answers.
*   **Cons:** WIRE-052 is closed. A new payload map needs a record-structure version, two decoders at intake, and a rollout order of intake, then factory, then devices. A payload-level map also doesn't fold per item, so a resurvey would leave old annotations on a new value.
*   **Reason for rejection:** the `<path>.probes` sibling uses the `.unit` precedent and needs no wire change (D3).

### Broad answers

#### Alternative C1: Fieldseal rolls answers up or stores a precision column
*   **Pros:** an analyst gets a ready category column.
*   **Cons:** it derives values, which INS-226, INS-228, INT-083 and INT-092 forbid. Precision is already in the recorded code.
*   **Reason for rejection:** the parent chain is carried as metadata, and roll-up happens downstream.

#### Alternative C2: Use `concept` parents as the answer hierarchy
*   **Pros:** one hierarchy instead of two (INS-242).
*   **Cons:** concepts must not change validation (INS-171), and whether a parent can be answered is validation.
*   **Reason for rejection:** `parent` decides what may be answered, `concept` stays descriptive, and a lint warns when they disagree (D6).

#### Alternative C3: Dotted codes such as `cereals.rice`
*   **Pros:** the hierarchy can be read from the code.
*   **Cons:** breaks path rules (INS-012, INS-126), code stability (INS-136) and the `.po` keys.
*   **Reason for rejection:** `parent:` on a flat list keeps every existing reader working.

#### Alternative C4: An author-written fallback question, or free rephrasing by the collector
*   **Pros:** covers numbers and text, not only choices.
*   **Cons:** a fallback is a second question per question, to write and to map. Free rephrasing brings back the wording drift probes remove.
*   **Reason for rejection:** hierarchical lists are the smaller, more general step. If the collectors meant the repeated block per food, a category-level repeat instance is added instead (Open Questions, D7).

### Verified entry

#### Alternative D1: Store a "confirmed" flag per value
*   **Pros:** analysts can filter on it directly.
*   **Cons:** if verification can't be skipped, the flag is always true, so it is a derived value. If it can be skipped, every analysis gains a third state.
*   **Reason for rejection:** the gate can't be bypassed, and intake re-checks it on replay (D4).

#### Alternative D2: Blind re-entry for everything, or a read-back tap for everything
*   **Pros:** one behaviour to learn.
*   **Cons:** blind re-entry on choices is awkward. A tap on typed values doesn't catch a misread number.
*   **Reason for rejection:** each kind of input gets the check that matches its error.

#### Alternative D3: Drop read-back, and use a soft rule with reasons instead
*   **Pros:** less to build. A soft rule already models "please confirm".
*   **Cons:** a soft rule is about suspicious values, not about checking with the interviewee that the answer was heard right.
*   **Reason for rejection:** kept, but scoped tightly to interviewer administration, inline, and never hold-to-confirm (D10). The recorded risk is that it is self-attested.

### Overlays

#### Alternative E1: The policy as a separate signed artefact
*   **Pros:** a policy can be loosened or tightened without republishing the base.
*   **Cons:** verifiers must fetch, pin and check one more artefact. A base and its policy can drift apart.
*   **Reason for rejection:** a policy inside the base's own signed bytes can't be detached from it. Loosening is a new base version with an explicit `relaxes:` marker (§7).

#### Alternative E2: Only `locked`, or appending only at the end
*   **Pros:** the simplest to verify, and it covers the case that prompted the work.
*   **Cons:** programmes that need a question in the middle of a survey can't use it.
*   **Reason for rejection:** named after-section points cost little more, because whole elements are still added at fixed places (D14).

#### Alternative E3: Publish overlays as deltas that runtimes merge at load
*   **Pros:** smaller overlay publications; the base is shared on the device.
*   **Cons:** every runtime would need merge logic, and a merge bug would change what is asked. The evaluator, render plan and intake would all become overlay-aware.
*   **Reason for rejection:** publishing the resolved instrument keeps evaluation unchanged. Only verification is overlay-aware, and it is one shared function (§6).

#### Alternative E4: Each verifier implements its own overlay check
*   **Pros:** none worth having.
*   **Cons:** four implementations drift apart, and one bug admits a bad overlay.
*   **Reason for rejection:** one pure function in the format core, with golden fixtures (§8, §9).

#### Alternative E5: Aids allowed in overlays, or a policy that lists the allowed aids
*   **Pros:** standards that permit approved probes could say so.
*   **Cons:** a blanket allowance breaks "read exactly as written". A per-policy list is another dimension to verify and explain.
*   **Reason for rejection:** the lock covers aids. A standard that wants probes adds them itself, in a new base version.

#### Alternative E6: One intake table per base, merging overlays
*   **Pros:** easier for analysts.
*   **Cons:** breaks "the fingerprint is the unit" (INT-070), leaves sparse columns, and risks mixing data whose rules interact.
*   **Reason for rejection:** separate tables with lineage columns make pooling a filter (D16).

#### Alternative E7: Overlays of overlays
*   **Pros:** a national overlay extended regionally is a real pattern.
*   **Cons:** the policy must be transitive and a digest kept per level, and verifiers must walk a chain.
*   **Reason for rejection:** one level for now. A `chainable` flag can be added later without a breaking change (D15).

#### Alternative E8: The licence decides the policy
*   **Pros:** a `-ND` licence would lock automatically.
*   **Cons:** it makes an SPDX string drive behaviour. It would also block a rights holder who may modify their own survey.
*   **Reason for rejection:** the licence produces lint warnings only. The policy is the control (D18).

#### Alternative E9: Only the base publisher may translate a locked base
*   **Pros:** the strictest guarantee of wording.
*   **Cons:** it blocks certified third-party translators, the main way standards reach new languages.
*   **Reason for rejection:** an optional `translators:` list, defaulting to the base publisher (D17).

## Non-Functional Requirements

### Security

*   **Verification fails closed.** `overlay::check` and `verify_overlay` return findings, and any finding of severity error refuses the overlay in all four verifiers; there is no path that accepts with a warning (Goals). Specifically:
    *   A verifier that cannot get the base (not in the registry, not in the bundle, not verified, wrong kind, withdrawn for a new build) refuses. It never trusts the overlay's own claim about its base.
    *   The base's canonical bytes are compared with the overlay's projection, never a digest the overlay supplies (§6).
    *   An unknown policy value, an unknown key and a malformed key id are refused by the strict decoder (INS-006). A policy that the runtime does not understand is a refusal, not a default to `modify`.
    *   The check is one function (PUB-134). The matrix in Phase 16 runs every rule through all four verifiers from one vector file, so a verifier that drifts fails a test.
*   **Policy downgrade.** The check needs the earlier versions of the base's name, which only a registry holds (the log has no names, PUB-104). So it runs where a registry exists: `artefact publish` before `put`, and the factory at bundle build. A device and intake hold no history and do not run it. Their protection is that the factory refused to sign such a bundle, and that the policy is inside the base's signed bytes. The weakening is visible in review because `relaxes` names the earlier version (PUB-011).
*   **Signer allow-lists.**
    *   Only signatures that the publisher threshold counts (PUB-040) can satisfy a list. The list names key ids from the trust bundle and adds no key role. A revoked key fails in `VerifyPublication` before the list is read.
    *   With no `translators` list a translation of a `locked` or `extend` base needs a key of the base's own publisher. With no `overlayPublishers` list any trusted publisher may add to a `modify` or `extend` base (D19). This second default is open on purpose and is the owner's decision.
*   **Who may read probe paradata.**
    *   `.probes` rows are ordinary observations. They are readable by exactly the roles that read the other landed data: the custodian role for raw rows (INT-060) and the results reader and CLI for the pseudonymised export (INT-087, INT-089).
    *   The subject is pseudonymised in the export, but `record_id`, `tenancy` and `seq` identify the device account that collected, so probe use is information about the collector. This design adds no collector dashboard, no score and no per-collector report. The contract and codebook mark the data self-reported, and an empty set means none recorded.
    *   A later advisory field check for probe-use rate (the brief's collector QA idea) needs its own review, because it monitors individuals.
*   **First entries are never stored.** A retype first entry lives in a page variable until the second entry matches. It is not in a form value, a log line, a pending record, a journal or a pause. Autofill, paste and IME suggestions are off on the second field.
*   **Nothing else in the trust model changes.** No new signing key, certificate role, or policy control is added. The wire change is one optional list in the bundle plaintext (WIRE-094), inside the existing seal and signature.

### Performance

*   **Bundle size.**
    *   A resolved overlay contains the whole base content plus the added elements, and the bundle also carries the base's publication for verification. Expect about twice the base's size plus a few kilobytes of signatures, log records and one checkpoint. For scale: the expanded school-meals instrument is 32 KB as JSON, and the limit is 64 MiB (`MAX_BUNDLE_FILE`). The factory refuses a plaintext over its limit before sealing or signing.
    *   Probes add about 15 to 20 KB per language for 40 questions (brief, §2). Carried bases are not deduplicated across overlays; a device holds one instrument per bundle, so there is nothing to share yet (Future Improvements).
*   **Code-list clone cost.** `Reader::list` clones the whole `CodeList` on each call, and `set_value` evaluates twice (`capture.rs:331` and `341`), so a large food or occupation tree is copied twice per tap on a low-end phone. Phase 6 changes `Reader::list` to borrow, which removes the cost before hierarchies make lists larger. `CodeList::chain` costs O(depth) per held code, plus a lookup per level. A conformance check with a 2,000-code, 3-level list runs 100 `set_value` calls inside a generous bound, so a regression to cloning is caught without a flaky timing test.
*   **Evaluation twice per `set_value`.** `within` adds one node per call (INS-044). `verify_required` is computed in the same pass as the rules, so verification adds no third evaluation. The overlay adds nothing at run time, because the resolved instrument evaluates like any other.
*   **Verification cost.** `overlay::check` is linear in the size of the two canonical documents and runs once per `survey check`, publish, bundle build, bundle import and unlock, and once per overlay in intake per gate (memoised by address pair, Phase 13). It is not on the capture path.

### Accessibility

*   **Blind re-entry.**
    *   The second field has its own visible label, "Type it again", and the question says "entered twice" before the first entry (WEB-186, WCAG 3.3.2, 1.3.1).
    *   A mismatch is announced in a `role=status` live region (WCAG 4.1.3) and is also shown as text near the field, not by colour alone (1.4.1).
    *   Blind re-entry conflicts with WCAG 2.2 SC 3.3.7 (Redundant Entry). The "essential" exception applies, because the second entry is a check that must not be pre-filled. WEB-202 documents this, as INS-257 and WEB-192 are tested against it.
    *   Autofill and IME suggestions are off, and paste is refused, with a catalogued message (PLAT-050). A password manager is not offered (3.3.8 is about sign-in, not about this field).
*   **Chips and actions.** Probe chips and the broad-answer action are buttons with an accessible name and `aria-pressed`, at least 24 by 24 CSS pixels (2.5.8), not hidden under sticky content when focused (2.4.11), and reflow at 320 px (1.4.10). Their visible text is part of their accessible name (2.5.3).
*   **Read-back.** It is one tap, never hold-to-confirm, so a keyboard user and a switch user have the same single action (INS-024, WEB-185 are about sealing and stay as they are).
*   **Android.** AND-027 blocks TalkBack by default on managed devices. There is no Android UI yet (D13), so this is recorded for the native work and tested nowhere here.
*   **How it is tested.** `just a11y` runs axe-core for WCAG 2.0, 2.1 and 2.2 A and AA plus the four extra checks over the corpus page with each control in its open state (Phase 9), and over the examples (Phase 18).

### Rollout and rollback

*   **Rollout.** Schema 1.0 is amended in place before v0.1.0 (D1). No released device or record exists, so nothing is migrated. The one thing that can go wrong is a build from another commit: it disagrees on fingerprints. The runbook (Phase 19) says to build the CLI, the factory and the web device from one commit, run `just purge` on a local stack, and republish the examples with bases before overlays.
*   **The model phases change no signed byte.** Every new canonical field is written only when used (§2), and plan fields only when not empty, so the golden set and `additive_schema` stay green from Phase 1 to Phase 17. Only Phase 18 moves addresses.
*   **Rollback.**
    *   Each phase is one revertible commit, reverted in reverse order. Reverting Phase 18 alone restores the previous examples and goldens, and passes `just test`, because the model still accepts the old documents (the revert rehearsal in its gate).
    *   Reverting a model phase after Phase 18 would leave migrated examples that use keys the old model rejects (the decoder is strict, INS-006), so it needs Phase 18 reverted first.
    *   A local stack that has published a migrated survey and then rolls back must be purged (`just purge`), for the same reason.

### Additional Resources

*   **Specifications** (`docs/reference/spec/`): [instrument.md](../reference/spec/instrument.md) (INS-006, INS-012, INS-090 to INS-092, INS-112, INS-131 to INS-143, INS-150, INS-151, INS-164, INS-200, INS-228, INS-242, INS-252 to INS-260, and the new INS-262 to INS-288), [publishing.md](../reference/spec/publishing.md) (PUB-011, PUB-020 to PUB-022, PUB-040, PUB-090 to PUB-104, PUB-128 to PUB-134), [distribution.md](../reference/spec/distribution.md), [collection.md](../reference/spec/collection.md), [intake.md](../reference/spec/intake.md), [wire-formats.md](../reference/spec/wire-formats.md) (WIRE-004, WIRE-052, WIRE-094, WIRE-211 to WIRE-213), [web-app.md](../reference/spec/web-app.md), [cli.md](../reference/spec/cli.md), [platform-profiles.md](../reference/spec/platform-profiles.md).
*   **ADRs:** [0028 clean architecture](../explanation/adr/0028-clean-architecture.md), [0030 public transparency log](../explanation/adr/0030-public-transparency-log.md), [0032 standard survey elements](../explanation/adr/0032-standard-survey-elements.md), [0034 internationalisation](../explanation/adr/0034-internationalisation-and-localisation.md), [0037 extensions and strict schema enforcement](../explanation/adr/0037-extensions-and-strict-schema-enforcement.md), [0040 compact declarations](../explanation/adr/0040-compact-declarations-and-twelve-factor-config.md), [0041 survey source tree](../explanation/adr/0041-survey-source-tree-and-authoring-toolchain.md). This design adds 0042 and 0043.
*   **The brief:** [`concepts_brief.field-collection-aids.md`](../../concepts_brief.field-collection-aids.md), with the reviewers' findings and decisions D1 to D19.
*   **Reference pages:** [survey folder](../reference/survey-folder.md), the new [survey dialect](../reference/survey-dialect.md), [conformance](../reference/conformance.md), [test inventory](../reference/test-inventory.md), [glossary](../reference/glossary.md).
*   **External:** WCAG 2.2 success criteria 1.3.1, 1.4.1, 1.4.10, 1.4.12, 2.4.11, 2.5.3, 2.5.8, 3.3.2, 3.3.7, 4.1.2 and 4.1.3; Unicode Standard Annex 15 (normalisation form C).

### Future Improvements

*   **Deduplicate bases in bundles.** Carry a base once per tenancy when several assigned overlays share it. It matters only after a bundle can hold more than one instrument.
*   **Chainable overlays.** An overlay of an overlay with a `chainable` flag in the base, a policy that takes the weakest level, and verifiers that walk a chain (D15).
*   **A read-aloud field for `administration: both`.** The name `read-aloud` (or `wording`) is reserved (D2, D12). It comes with per-capture administration mode.
*   **Per-capture administration mode.** Record whether a capture was administered or self-filled, then allow probes and read-back on `both` surveys (D11).
*   **Multi-major schema support.** Runtime and intake keep more than one major (#45, INS-092, WIRE-130), before the first real major.
*   **Category-level repeat instances.** Only if the collectors' answer to D7 is the food-frequency case.
*   **Paradata.** Store retype mismatch counts, and add advisory field checks for probe-use and broad-answer rates, after a privacy review of monitoring collectors.
*   **Drill-down presentation** for very large trees, and a check-digit rule function for identifiers.
*   **Send the runtime's constraint kinds in the registration profile** (WIRE-130), so the factory can refuse an incompatible runtime before building, instead of the device refusing at import.

## Detailed Implementation Plan

The work is split into 19 phases. Each is one revertible commit (or a small named series) and ends with a gate that must pass before the next phase starts. A phase is ordered after everything it calls, so every phase leaves the tree green. The order follows the dependencies of the Technical Plan:

*   **Part A prerequisites first** (Phases 1 to 4): the authoring fixes (#26), the annotation-suffix refactor (#31, first half), the constraint kinds in `CheckCompatibility` (#29) and the shared constraint corpus (#33). Nothing that adds a new item suffix or a new constraint can land before them.
*   **Part A features** (Phases 5 to 11): probes with the second half of #31 (the `.probes` item needs the module of Phase 2), hierarchy, verified entry, the intake contract and export, the web UI and the bindings, then ADR 0042. The UI phase follows the core phases because it calls their APIs; the ADR follows because it records what the code settled.
*   **Part B** (Phases 12 to 17): the policy, overlay model and check, then authorisation and the four verifiers, intake lineage, the licence and translation lint, the fixtures and ADR 0043.
*   **Last** (Phases 18 and 19): the examples migration with the one re-baseline of goldens and the migration gate (#36), and the runbook (#37).

Two rules hold through the whole plan.

*   **No signed byte moves before Phase 18.** New canonical fields are written only when used and new plan fields only when not empty. `just migration-gate` and `additive_schema` (Phase 1) stay green in every earlier phase. The migrated examples are the only reason an address changes, so the golden set changes once.
*   **A requirement and its tests land together.** `tools/test-inventory.py --check` does not count a test that names a requirement no spec defines. Each phase therefore edits the spec in the same commit as the code and the tests.

### Phases

| Phase | Name | Issues | Security review | Gate (summary) |
|---|---|---|---|---|
| 1 | Stage 0 authoring fixes and the additive-schema pin | #26 | None | `nix develop path:. -c just test`; `cargo nextest run -p fieldseal-e2e --test additive_schema`; `just migration-gate` unchanged; the committed dialect page equals `schema export --markdown`. |
| 2 | Annotation-suffix refactor (first half of #31) | #31 | None | `nix develop path:. -c just test`; `just migration-gate` unchanged; `fieldseal conformance run --suite col-lifecycle`; the stray-`.unit` tests fail on the old code and pass on the new. |
| 3 | Constraint kinds in `ControlCatalogue` and `CheckCompatibility` | #29 | None | `nix develop path:. -c just test`; `fieldseal conformance run --suite instrument,col-lifecycle`; a device rejects a bundle whose instrument needs an unlisted kind and keeps its earlier bundle. |
| 4 | Shared constraint corpus and the `ins-ui-constraints` suite | #33 | None | `nix develop path:. -c just test`; `fieldseal conformance run --suite ins-ui-constraints`; `FIELDSEAL_BROWSER_TESTS=1 cargo test -p fieldseal-web --test browser_constraints`; no check of the old browser script is lost. |
| 5 | Probes and the `.probes` item (#27, second half of #31) | #27, #31 | None | `nix develop path:. -c just test`; `fieldseal conformance run --suite ins-probes,strict-schema`; `just migration-gate` and `additive_schema` unchanged; the golden plans do not change. |
| 6 | Hierarchical code lists, broad answers and `within()` | #28 | None | `nix develop path:. -c just test`; `fieldseal conformance run --suite ins-hierarchy,ins-rules,ins-eval,ins-ui-constraints`; `just migration-gate` unchanged. |
| 7 | Verified entry in the core | #30 | None | `nix develop path:. -c just test`; `fieldseal conformance run --suite ins-verify,col-verify,ins-ui-constraints`; the CLI device simulator seals a retyped value and refuses an unverified one. |
| 8 | Intake contract, codebook and export 1.1.0 | #32 | None | `nix develop path:. -c just test`; `cargo nextest run -p fieldseal-adapters-landing-files`; `cargo nextest run -p fieldseal-cli --test intake_results`; `LONG_COLUMNS` still has 20 columns. |
| 9 | Web UI and HTML renderer | #34 | None | `nix develop path:. -c just test`; `FIELDSEAL_BROWSER_TESTS=1 cargo test -p fieldseal-web --test browser_constraints` with the aid scenarios; `just a11y`; `tools/dev-web.sh --check --browser`. |
| 10 | Bindings: wasm, UniFFI, Python | #35 | None | `nix develop path:. -c just test`; `tools/test-python-vectors.sh`; `tools/dev-web.sh --check --browser` (the wasm device calls the new methods). |
| 11 | ADR 0042 and the documentation of Part A | #25 | None | `nix develop path:. -c just test`; every link in the new and changed documents resolves; ADR 0042 stays Proposed until the answer to D7 is recorded in it. |
| 12 | Modification policy, overlay model and `survey check` (overlay) | #38, #39 | Owner sign-off (what a verifier accepts) | `nix develop path:. -c just test`; `fieldseal conformance run --suite ins-overlay,strict-schema`; `just migration-gate` and `additive_schema` unchanged; `survey check` on a scaffolded overlay passes and on a changed-label overlay exits 1. |
| 13 | Authorisation and the four verifiers | #40 | Owner sign-off (what a verifier accepts) | `nix develop path:. -c just test`; `fieldseal conformance run --suite publishing,distribution,ins-overlay`; `cargo nextest run -p fieldseal-security-tests`; `cargo nextest run -p fieldseal-factory`; `just acceptance`. |
| 14 | Overlay lineage at intake | #41 | None | `nix develop path:. -c just test`; `cargo nextest run -p fieldseal-adapters-landing-files`; `just acceptance`. |
| 15 | Licence and translation lint | #42 | None | `nix develop path:. -c just test`; `cargo nextest run -p fieldseal-cli --test survey_cli`. |
| 16 | Overlay fixtures and the four-verifier matrix | #43 | None | `nix develop path:. -c just test`; `cargo nextest run -p fieldseal-e2e --test overlay_matrix`; `fieldseal conformance run --suite all`; every case of `vectors.json` has an accepted or refused twin. |
| 17 | ADR 0043 and the documentation of Part B | #44 | None | `nix develop path:. -c just test`; links resolve; ADR 0043 states its risks. |
| 18 | Examples migration and the one re-baseline | #36 | None | `nix develop path:. -c just test`; `just migration-gate` against the regenerated goldens; `just acceptance`; `just a11y`; `tools/dev-web.sh --check --browser`; a revert rehearsal of this commit restores the previous goldens and examples and `just test` passes. |
| 19 | Rollout runbook | #37 | None | `nix develop path:. -c just test`; links resolve; the runbook's commands are the ones in `justfile`. |

Housekeeping that every phase also does, and that the entries below do not repeat: regenerate `docs/reference/test-inventory.md` (`python3 tools/test-inventory.py`) and `docs/reference/conformance.md` (`fieldseal conformance matrix`) when tests or suites change, update `Cargo.lock` and the touched crates' README contracts (for example `crates/contexts/instrument/src/domain/README.md`), and run no `cargo fmt`.

### New requirement ids

Allocated from the next free number in each spec. INS-261, INT-092, PUB-127, DIS-084, COL-110, CLI-055 and WEB-199 are the highest in use today. The Technical Plan's table names INT-013 for the intake reason, but INT-013 is the duplicate rule, so the reason is INT-093 (the earlier section is corrected). Every id below is defined in its spec in the phase shown.

| Id | Phase | Requirement |
|---|---|---|
| INS-262 | 5 | A question MAY list `probes: [{id, text}]` with stable unique slug ids; the text is localised and collector-only. |
| INS-263 | 5 | A probe missing or stale in a declared language is an error; there is no fallback. |
| INS-264 | 5 | Probes are refused on `self` and `both` surveys until the administration mode is recorded per capture. |
| INS-265 | 2 | Annotation items (`<path>.unit`, `<path>.probes`) are named once in the format core, with their data type and fold rule. |
| INS-266 | 5 | The synthesised `<path>.probes` item holds the probe ids used; it is self-reported and an empty set means none recorded. |
| INS-267 | 6 | A code MAY name a `parent` of the same list; a forest at most 8 deep; listed combinations are errors. |
| INS-268 | 6 | A parent code is answerable only in a question that declares `broad-answer: allowed`; a broad answer is a value, not a nonresponse. |
| INS-269 | 6 | `within(path, code)` is true for the code or any descendant; `==`, `!=` and `in` stay exact. |
| INS-270 | 6 | In a multi-choice, a code and its ancestor MUST NOT both be selected. |
| INS-271 | 6 | Lints for leaf comparisons over a broad question, parent and concept disagreement, and sentinel-like labels. |
| INS-272 | 7 | `verify: retype|read-back`, where each is allowed, and an optional `when`. |
| INS-273 | 7 | Retype lifecycle: first entry never written, blind second entry, NFC equality, mismatch and pause outcomes. |
| INS-274 | 7 | Read-back lifecycle: inline, one tap, never hold-to-confirm, the collector speaks. |
| INS-275 | 7 | A required, unverified verify item blocks sealing as a value problem; nonresponse and carried-over values are exempt. |
| INS-276 | 5 | The path segments `probes`, `probe`, `extensions` and `base` are reserved (amends INS-012). |
| INS-277 | 1 | An interviewer survey's question MUST declare a `label` in the dialect; `short-label` sets `shortLabel`. |
| INS-278 | 1 | Lint: warn once per question whose label looks like a heading, with listed exemptions. |
| INS-279 | 3 | The constraint kinds are a closed list in the format core, and a control catalogue lists those its UI enforces. |
| INS-280 | 12 | `spec.modification` is `locked`, `extend` or `modify` (default `modify`); `extend` names extension points; `end` always exists. |
| INS-281 | 12 | An overlay names a published base and adds elements in `spec.extensions` slots; the resolved instrument is what is published; one level. |
| INS-282 | 12 | The overlay check: the projection of the overlay equals the base's canonical bytes minus its metadata; the first differing path is reported. |
| INS-283 | 12 | Content outside the base and the slots, or a slot for an undeclared point, is refused. |
| INS-284 | 12 | Added checks read base answers but do not `skip` or `derive` a base path; added paths live under `extensions.<point>`; added questions use inline lists. |
| INS-285 | 12 | An overlay with no `extend` that only adds languages is a translation. |
| INS-286 | 12 | `translators` and `overlayPublishers` are lists of publisher key ids. |
| INS-287 | 15 | Lint rules for licence and translation against the policy (advisory). |
| INS-288 | 13 | `relaxes` is the address of an earlier version of the same name whose policy this version weakens. |
| PUB-128 | 13 | An overlay's base MUST be a verified published instrument at `spec.base.address`. |
| PUB-129 | 13 | With `overlayPublishers` listed, an overlay with extensions MUST carry a counted signature by a listed key. |
| PUB-130 | 13 | A language-only overlay MUST carry a counted signature by a `translators` key, or by a key of the base's publisher when none is listed. |
| PUB-131 | 13 | A base weaker than the strongest earlier version of its name in the registry is refused unless `relaxes` names that version. |
| PUB-132 | 13 | Removing an extension point is tightening; adding one is relaxing and needs the marker. |
| PUB-133 | 13 | A withdrawn base blocks a new overlay or bundle; existing overlays and landed data stay valid. |
| PUB-134 | 13 | `verify_overlay` is the only implementation of the overlay check, used by every verifier. |
| DIS-085 | 13 | A bundle MAY carry `bases` for verification only; a base is never offered for capture. |
| DIS-086 | 13 | The factory refuses to build a bundle holding an overlay that fails `verify_overlay`; the previous bundle stays. |
| DIS-087 | 13 | A runtime rejects a bundle whose overlay lacks its base or fails `verify_overlay`, and keeps its earlier bundle. |
| COL-111 | 2 | Clearing or retracting an item clears its annotation siblings; setting a value without an annotation drops the earlier one. |
| COL-112 | 7 | The capture refuses to seal a required, unverified verify item and never writes a first entry; a pause leaves such values out. |
| COL-113 | 3 | On import a runtime runs `CheckCompatibility` with its own catalogue and rejects an incompatible bundle. |
| INT-093 | 13 | Intake verifies an overlay against its base on learning it and on replay, and holds the records of one that fails with that reason. |
| INT-094 | 8 | The data contract and codebook carry each code's parent and leaf flag and say probe use is self-reported. |
| INT-095 | 14 | Contract, codebook and manifest mark every overlay item `inherited` (with the base address) or `added`. |
| WEB-200 | 9 | The web app shows probe chips to the collector. |
| WEB-201 | 9 | The broad-answer action follows the probes and is secondary to the control. |
| WEB-202 | 9 | Blind re-entry: own label, paste refused, autofill off, live-region mismatch, 'entered twice' first; the SC 3.3.7 exception is recorded. |
| WEB-203 | 9 | Read-back is inline and one tap. |
| CLI-056 | 12 | `survey check` checks an overlay folder against its base; `new overlay` scaffolds one. |
| CLI-057 | 1 | `schema export --markdown` writes the dialect reference generated from the decoder's tables. |

Amended, not new: INS-012, INS-090, INS-092, INS-112, INS-131 to INS-137, INS-150, INS-151, INS-164, INS-228, INS-252 to INS-257, WIRE-094, PUB-104, DIS-010, DIS-030, INT-070, INT-071, INT-085, WEB-186, PLAT-067, PLAT-068, CLI-043, CLI-045.

### Entries by phase

Entries are numbered in phase order and are final. A file that several phases change appears once per phase.

| Phase | Entries |
|---|---|
| 1 | 1 to 19 |
| 2 | 20 to 32 |
| 3 | 33 to 46 |
| 4 | 47 to 56 |
| 5 | 57 to 81 |
| 6 | 82 to 108 |
| 7 | 109 to 130 |
| 8 | 131 to 139 |
| 9 | 140 to 158 |
| 10 | 159 to 165 |
| 11 | 166 to 175 |
| 12 | 176 to 202 |
| 13 | 203 to 239 |
| 14 | 240 to 248 |
| 15 | 249 to 252 |
| 16 | 253 to 267 |
| 17 | 268 to 276 |
| 18 | 277 to 309 |
| 19 | 310 to 313 |

### Target Files to Create/Modify

**Phase 1: Stage 0 authoring fixes and the additive-schema pin**

#### 1. `crates/kernel/src/schema.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Compact-dialect schema tables (kernel)
*   **Proposed Changes**: Add `short-label` (text) to `QUESTION_COMMON` (line 798), next to `label`, with the doc "A short label for summaries and the data contract." It expands to the existing canonical `shortLabel` (`decode.rs:886`). Change the `label` doc to say that it is required in an interviewer survey and is made from the id only in a self-administered one. Add a pure function `reference_markdown(kind: DocKind) -> String` that renders every shape and key (name, type, required, doc) as the Markdown tables of `docs/reference/survey-dialect.md`; it reads the same `SHAPES` table the decoder and `json_schema` read, so the page cannot drift. Later phases add their keys to this table and nothing else.

#### 2. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Compact-dialect expansion
*   **Proposed Changes**: In `Survey::expand` (line 297) keep the survey's `administration` (the key is read at line 312 only to be copied) in a new field of `Survey`. In `Survey::question` (line 712): (a) read `short-label` and emit `shortLabel` as a localised text with the context `<full path>.short-label` (so the `.po` key is `instrument/<path>.short-label`, which `po::check_context` already accepts); (b) replace the fallback at lines 721 to 725, which builds a label from the id, with an error `missing-label` (finding INS-277, pointer `<question>/label`) when the survey is `interviewer` and the question is not a `roster` item. Self-administered surveys keep the id fallback because nobody reads their labels aloud (INS-150). The survey `administration` default is not guessed: an absent `administration` is already an error in the decoder (`decode.rs:352`).

#### 3. `crates/contexts/instrument/src/application/lint.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Advisory lints
*   **Proposed Changes**: Add the heading-like label lint (INS-278) in the per-question loop that already checks `label`, `help` and `guidance` (line 185). A label is heading-like when it has at most three words and no question mark, comma or full stop. The finding is `Severity::Advice`, once per declared question. It skips: `roster` items (`from_roster`), `measurement-pair` questions, `photo-evidence` questions, repeat instances (the repeat's template is checked once), and synthesised questions (`origin` not `Authored`). It never changes validity, and `survey check --strict` leaves it as advice (the CLI prints lint findings with `strict` off, `survey_cmd.rs:75`).

#### 4. `crates/apps/cli/src/conformance_cmd/ins_labels.rs` (Create)

*   **Phase**: 1
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: Checks for INS-277 and INS-278, registered in `ins.rs` under a new suite `ins-labels` (also added to `SUITES` in `mod.rs`): a compact interviewer survey without a `label` is refused with `missing-label`; the same survey with `administration: self` expands; a three-word heading label gets one advice finding and a full question gets none; roster, `measure-twice` and photo items are exempt; the advice never changes `validate_instrument`.

#### 5. `crates/apps/cli/src/conformance_cmd/ins.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Instrument conformance registration
*   **Proposed Changes**: Register `ins_labels` checks (new table `LABELS`) and its suite name. Housekeeping for later phases: each later `ins_*.rs` module is registered here the same way and is not listed again.

#### 6. `crates/apps/cli/src/conformance_cmd/mod.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Conformance suite list
*   **Proposed Changes**: Add `mod ins_labels;` and the suite `ins-labels` to `SUITES` (line 125). Later phases add `ins-probes`, `ins-hierarchy`, `ins-verify`, `ins-overlay`, `ins-ui-constraints` and `col-verify` the same way.

#### 7. `crates/apps/cli/src/schema_cmd.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: CLI: schema export
*   **Proposed Changes**: Add the boolean flag `--markdown` to `schema export` (`run`, line 22; `export`, line 44). With `--kind survey|layout` it writes `schema::reference_markdown(kind)` instead of the JSON Schema; `--out` works as before. It prints no schema address, because the page is documentation, not a signed document (CLI-057). Later phases add `--kind overlay` (Phase 12).

#### 8. `docs/reference/survey-dialect.md` (Create)

*   **Phase**: 1
*   **Type / Scope**: Reference
*   **Proposed Changes**: The normative list of every compact-dialect key of surveys and layouts (survey, list, item, question types, condition operators, checks, field checks, layout steps and contents). The body between two marker comments is the output of `fieldseal schema export --kind survey --markdown` and the layout equivalent; a test fails when it differs. A short preface says what the dialect is and links ADR 0040 and 0041. It is the home for the keys that Phases 5, 6, 7 and 12 add.

#### 9. `flake.nix` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Nix source set
*   **Proposed Changes**: Add `./docs/reference/survey-dialect.md` to the `workspaceSrc` fileset (line 96 to 108), because the drift test reads it and the sandbox holds only the listed documents.

#### 10. `docs/reference/survey-folder.md` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Reference
*   **Proposed Changes**: Link the dialect page from the first paragraph. Add the `missing-label` row to the `survey check` findings table (INS-277, error). Say in one sentence that the heading-like label lint is advisory and exempts roster, measurement and photo items. Phase 12 adds the overlay folder.

#### 11. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-277 (an interviewer survey's question MUST declare a `label` in the authoring dialect; only a self-administered survey may have it made from the id; a `short-label` key sets `shortLabel`) and INS-278 (lint: SHOULD warn once per declared question whose label looks like a heading; roster, measurement, photo, repeat-instance and synthesised questions are exempt). Amend INS-150 to point at INS-277. Add both ids to the traceability table at the end of the document.

#### 12. `docs/reference/spec/cli.md` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add CLI-057: `schema export` MUST accept `--markdown`, writing the dialect reference of the kind, generated from the same table the decoder reads. Add `missing-label` to the findings of CLI-045.

#### 13. `crates/adapters/authoring/tests/fixtures/surveys/missing-label/instrument.yaml` (Create)

*   **Phase**: 1
*   **Type / Scope**: Test fixture
*   **Proposed Changes**: A minimal interviewer survey whose single question has no `label`.

#### 14. `crates/adapters/authoring/tests/survey_resolver.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: Authoring tests
*   **Proposed Changes**: Add `ins_277_an_interviewer_question_without_a_label_is_refused_at_its_pointer` and `ins_277_a_short_label_expands_to_short_label_with_its_own_po_key`, using the new fixture and the existing `valid` fixture.

#### 15. `crates/apps/cli/tests/survey_cli.rs` (Modify)

*   **Phase**: 1
*   **Type / Scope**: CLI tests
*   **Proposed Changes**: Add `cli_057_the_committed_dialect_reference_equals_the_generated_one` (runs `schema export --kind survey --markdown` and `--kind layout --markdown` and compares the marked bodies of `docs/reference/survey-dialect.md`) and `ins_277_survey_check_reports_missing_label_with_its_position`.

#### 16. `crates/apps/e2e/tests/fixtures/pre-amendment/school-meals-baseline/instrument.yaml` (Create)

*   **Phase**: 1
*   **Type / Scope**: Test fixture
*   **Proposed Changes**: A byte copy of `examples/surveys/school-meals-baseline/instrument.yaml` as it is before Phase 18. It never changes. It is the proof that an instrument that uses none of the new keys keeps its canonical bytes (§2).

#### 17. `crates/apps/e2e/tests/fixtures/pre-amendment/school-meals-baseline/i18n/es.po` (Create)

*   **Phase**: 1
*   **Type / Scope**: Test fixture
*   **Proposed Changes**: A byte copy of the example's Spanish catalogue before Phase 18.

#### 18. `crates/apps/e2e/tests/golden/pre-amendment.json` (Create)

*   **Phase**: 1
*   **Type / Scope**: Golden record
*   **Proposed Changes**: The instrument address, salted fingerprint and salt of the pre-amendment fixture, copied from `examples.json` as it is today. Unlike `examples.json` it is never re-baselined.

#### 19. `crates/apps/e2e/tests/additive_schema.rs` (Create)

*   **Phase**: 1
*   **Type / Scope**: End-to-end test
*   **Proposed Changes**: `ins_200_an_instrument_that_uses_no_new_key_keeps_its_address_and_fingerprint`: loads the fixture through the resolver, addresses it as `migration_gate.rs` does (`record`, line 41) and compares with `pre-amendment.json`. It runs in every phase, so a model change that alters bytes for an unchanged instrument fails at once. Covers INS-200.

**Phase 2: Annotation-suffix refactor (first half of #31)**

#### 20. `crates/contexts/instrument/src/domain/annotation.rs` (Create)

*   **Phase**: 2
*   **Type / Scope**: Format core: annotation items
*   **Proposed Changes**: One module that names the sibling items a question can carry. `enum Annotation { Unit, Probes }` with: `suffix(self) -> &'static str` (`.unit`, `.probes`), `split(path: &str) -> Option<(&str, Annotation)>` (the base path and the kind), `item_path(base: &str, kind: Annotation) -> String`, `data_type(self) -> DataType` (`.unit` records text; `.probes` records codes), and `on_value_set(self) -> Fold` (`Replace` for `Unit`: a value set without a unit drops the old unit, as `landing.rs:100` does today; `Keep` for `Probes`: setting the value does not touch the probe set, §3) and `clears_with_value(self) -> bool` (both kinds: clearing or retracting the base drops the annotation). `Probes` is declared here but no question yields it until Phase 5. This replaces every literal `".unit"` listed in the entries below. Covers INS-265.

#### 21. `crates/contexts/instrument/src/domain/mod.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Format core exports
*   **Proposed Changes**: `pub mod annotation;` and re-export `Annotation`.

#### 22. `crates/contexts/instrument/src/domain/evaluation.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Format core: evaluation
*   **Proposed Changes**: Lines 242 to 245 (the entry unit read next to a value) and 364 to 371 (`Reader`, the consumed `.unit` key) call `annotation::item_path` and `annotation::split` instead of `format!("{}.unit", …)`. When a base value is unset or hidden, its `Annotation::Unit` sibling is ignored, not reported as an unknown path. No behaviour change otherwise.

#### 23. `crates/contexts/collection/src/domain/capture.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Collection: pending capture
*   **Proposed Changes**: `editable` (line 313 to 316) and `set_value` (line 332) use `annotation::split` instead of `strip_suffix(".unit")`. `clear_value` (line 345) also removes every annotation sibling of the cleared path. This fixes a bug confirmed by reading the code: clearing an item with an entry unit leaves its `.unit` in `values`, where it is evaluated as an unknown sibling and kept in the pending record.

#### 24. `crates/contexts/collection/src/domain/local.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Collection: local fold
*   **Proposed Changes**: `fold` (lines 103 to 109) removes a retracted item from `current` but not its annotation siblings. It now removes the siblings through `annotation::item_path` for each `Annotation` kind. This is the second place of the same bug.

#### 25. `crates/contexts/intake/src/landing.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Intake: landing
*   **Proposed Changes**: `apply` (lines 100 to 119), the value-row builder (lines 229 and 253) and the hidden-item removal use `annotation::split` and `item_path`. The behaviour is unchanged (intake already drops the `.unit` of a replaced or retracted value); the test below pins it.

#### 26. `crates/adapters/html/src/render.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: HTML renderer
*   **Proposed Changes**: Line 1026 (the chosen entry unit read from `values`) uses `annotation::item_path(bind, Annotation::Unit)`.

#### 27. `crates/adapters/html/src/page.js` (Modify)

*   **Phase**: 2
*   **Type / Scope**: HTML page script
*   **Proposed Changes**: Line 518 strips the `.unit` suffix with a regular expression. Move the suffix list to one constant `ANNOTATION_SUFFIXES` at the top of the script and build the expression from it. The script cannot call Rust, so the constant is checked against the Rust list by the parity test below.

#### 28. `crates/apps/web/assets/answers.js` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Web assets
*   **Proposed Changes**: `readAnswers` (lines 41 to 51) builds `<path>.unit` from a constant `ANNOTATION_UNIT` defined once in this module and exported for `device.js` and `instrument.js`.

#### 29. `crates/apps/web/tests/parity.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Web tests
*   **Proposed Changes**: Add `ins_265_the_script_suffix_lists_equal_the_core_list`: reads `ANNOTATION_SUFFIXES` from `page.js` and the constant of `answers.js` and compares them with `Annotation` suffixes.

#### 30. `crates/apps/cli/src/conformance_cmd/col.rs` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Collection conformance checks
*   **Proposed Changes**: Add `col_111_clearing_or_retracting_an_item_takes_its_annotation_siblings_with_it`, for the pending capture (`clear_value`) and the local fold (`fold`), and `col_111_a_value_set_without_its_unit_drops_the_old_unit`. Suite `col-lifecycle`.

#### 31. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-265: a sibling item `<path>.<annotation>` is an annotation of the item; the format core names the annotations (`unit`, `probes`), each with its data type and fold rule; no component may recognise an annotation by its suffix text outside that module.

#### 32. `docs/reference/spec/collection.md` (Modify)

*   **Phase**: 2
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add COL-111: clearing or retracting an item MUST clear its annotation siblings, in the pending capture and in the local fold; setting a value without an annotation MUST drop the earlier one.

**Phase 3: Constraint kinds in `ControlCatalogue` and `CheckCompatibility`**

#### 33. `crates/contexts/instrument/src/domain/constraints.rs` (Create)

*   **Phase**: 3
*   **Type / Scope**: Format core: constraint kinds
*   **Proposed Changes**: `enum ConstraintKind` with the nine kinds of the INS-252 table (`MaxChoices`, `ExclusiveCodes`, `Bounds`, `Grid` for step, decimals and currency digits, `MaxLength`, `OtherText`, `ListedCodes`, `EntryUnits`, `Required`), `name(self) -> &'static str` (kebab-case, stable), `ALL: [ConstraintKind; N]`, and `fn constraint_kinds(control: &Control, question: &QuestionNode) -> BTreeSet<ConstraintKind>`: the kinds a question uses, read from its control and data. Phases 6 and 7 add `BroadAnswer`, `AncestorExclusion`, `VerifyRetype` and `VerifyReadBack`. Covers INS-279.

#### 34. `crates/contexts/instrument/src/domain/mod.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Format core exports
*   **Proposed Changes**: Export `constraints`.

#### 35. `crates/contexts/instrument/src/ports.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Driven port: ControlCatalogue
*   **Proposed Changes**: Add `fn constraint_kinds(&self) -> Vec<ConstraintKind>` to `ControlCatalogue` (line 11 to 43) and `fn enforces(&self, kind) -> bool` with a default through `constraint_kinds`, as `supports` works for controls. There is no default list: an implementer must state what its UI enforces, because a default would claim enforcement that nobody tested (INS-254).

#### 36. `crates/contexts/instrument/src/application/compatibility.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: CheckCompatibility
*   **Proposed Changes**: `CompatibilityReport` gains `unsupported_constraints: Vec<ConstraintKind>`; `is_compatible` (line 29) requires it to be empty; `check_instrument` (line 38) collects the kinds the instrument uses with `constraint_kinds` and keeps those the catalogue does not list. Covers INS-254, INS-279.

#### 37. `crates/contexts/instrument/src/contract.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Port contract tests
*   **Proposed Changes**: `control_catalogue_contract` (line 8) also asserts that `enforces` agrees with `constraint_kinds` and that every kind of `ConstraintKind::ALL` is either listed or reported unsupported.

#### 38. `crates/adapters/memory/src/instrument.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: In-memory adapter
*   **Proposed Changes**: `FullCatalogue::constraint_kinds` returns `ConstraintKind::ALL`: the headless runtime enforces every kind in the core (`Capture` and the evaluator), which is what the CLI device and the simulator use.

#### 39. `crates/contexts/collection/src/application/mod.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Collection: platform
*   **Proposed Changes**: `Platform` (line 162) gains `pub catalogue: &'a dyn ControlCatalogue`, the controls and constraint kinds this runtime's UI enforces. Collection already depends on the Instrument context, so no dependency edge is added.

#### 40. `crates/contexts/collection/src/application/bundle.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Collection: bundle import
*   **Proposed Changes**: `verify_bundle` (line 134) calls `check_instrument(self.p.catalogue, &instrument)` after `validate_instrument` (line 141). An incompatible instrument rejects the whole bundle with a new `CollectionError::IncompatibleInstrument { address, unsupported }` naming the controls, presentations and constraint kinds, and the device keeps its earlier bundle (DIS-031). This is the first call of `CheckCompatibility` by a runtime; before it only the schema range was checked, in Distribution.

#### 41. `crates/adapters/memory/src/collection.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: In-memory adapter
*   **Proposed Changes**: The `Platform` literal (line 1121) passes `&FullCatalogue`.

#### 42. `crates/adapters/web/src/device.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Web device host
*   **Proposed Changes**: The `Platform` literal (line 293) passes a `WebCatalogue` defined in this file. It lists the controls the web UI renders and, as of this phase, the nine constraint kinds of INS-252 that `page.js` enforces. Phases 6, 7 and 9 add the kinds the web UI gains.

#### 43. `crates/apps/cli/src/conformance_cmd/ins_clinic.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: The two test catalogues (`Small`, line 101, and `FullAll`, line 120) implement `constraint_kinds`. Add `ins_254_an_instrument_using_an_unlisted_constraint_kind_is_incompatible` and `ins_254_a_catalogue_that_lists_every_kind_is_compatible`.

#### 44. `crates/apps/cli/src/conformance_cmd/col.rs` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Collection conformance checks
*   **Proposed Changes**: Add `col_113_a_bundle_whose_instrument_needs_an_unlisted_kind_is_rejected_and_the_old_bundle_kept`. Suite `col-lifecycle`.

#### 45. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-279: the constraint kinds are a closed list in the format core; the control catalogue MUST list the kinds its UI enforces and has no default. Amend INS-254 to name `unsupported_constraints` in the compatibility report.

#### 46. `docs/reference/spec/collection.md` (Modify)

*   **Phase**: 3
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add COL-113: on import a runtime MUST run `CheckCompatibility` with its own catalogue on every instrument, and MUST reject the bundle, keeping the earlier one, when the instrument is not compatible.

**Phase 4: Shared constraint corpus and the `ins-ui-constraints` suite**

#### 47. `tests/constraints/README.md` (Create)

*   **Phase**: 4
*   **Type / Scope**: Shared corpus
*   **Proposed Changes**: What the corpus is (INS-255), the scenario file format, how to add a scenario, and the three harnesses that run it: the core (`ins-ui-constraints`), the HTML renderer and the web device in a browser. A UI that does not pass a scenario does not ship.

#### 48. `tests/constraints/surveys/constraints-corpus/instrument.yaml` (Create)

*   **Phase**: 4
*   **Type / Scope**: Shared corpus: golden instrument
*   **Proposed Changes**: One interviewer survey in English with one question per constraint of INS-252: a multi-choice with `max: 4`, a list with an exclusive code, `number`, `stepper`, `money` and `date` questions with bounds and grids, a text with `max-length`, a list with `other`, a scale, a `measure-twice` with entry units, and a required question. Original content. Later phases add questions for probes, broad answers and verification to this same file.

#### 49. `tests/constraints/scenarios.json` (Create)

*   **Phase**: 4
*   **Type / Scope**: Shared corpus: scenarios
*   **Proposed Changes**: An array of scenarios, each `{id, requirement, question, mode: first|resurvey, steps: [{do: type|paste|choose|step|set, value}], expect: accepted|refused, message, pending_unchanged}`. For each INS-252 row it holds the cases INS-256 requires: at the limit (accepted), beyond it (refused), the same by paste or programmatic input (refused), and an unchanged pending record. The fifth option where `max` is 4, 100 in a field whose maximum is 20, and a second exclusive code are named scenarios.

#### 50. `crates/apps/cli/src/conformance_cmd/ins_ui.rs` (Create)

*   **Phase**: 4
*   **Type / Scope**: Conformance: ins-ui-constraints (core harness)
*   **Proposed Changes**: Reads `tests/constraints/scenarios.json` (embedded with `include_str!`, as `strict_schema.rs` embeds its corpus) and plays each scenario against `Capture` in first and resurvey modes: the core is the second line of INS-253, so a refused entry must not change the pending record and a value the UI would have refused must be reported as a value problem at seal. Registered as suite `ins-ui-constraints` (CLI-043, which names this suite but has no implementation today).

#### 51. `crates/apps/cli/src/conformance_cmd/mod.rs` (Modify)

*   **Phase**: 4
*   **Type / Scope**: Conformance suite list
*   **Proposed Changes**: Add `mod ins_ui;` and the suite `ins-ui-constraints` to `SUITES`.

#### 52. `tools/browser-tests/constraints.py` (Modify)

*   **Phase**: 4
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: Replace the hard-coded food and water checks with a driver that reads `scenarios.json` and plays every scenario in headless Chromium against the rendered corpus page (typing, paste events, ticking, pressing `+`, programmatic `value` set), asserting the expected outcome, the message and the unchanged answer set. The existing assertions (fifth option, 100 in a 20-maximum field, exclusive codes, stepper bounds, money maximum) are scenarios now, so no check is lost.

#### 53. `crates/apps/web/tests/browser_constraints.rs` (Modify)

*   **Phase**: 4
*   **Type / Scope**: Web tests
*   **Proposed Changes**: Render `constraints-corpus` (`/instruments/constraints-corpus/render`) instead of the two examples and pass the page and `scenarios.json` to the script. The test still skips unless `FIELDSEAL_BROWSER_TESTS=1`.

#### 54. `tools/browser-tests/README.md` (Modify)

*   **Phase**: 4
*   **Type / Scope**: Documentation
*   **Proposed Changes**: Describe the new `constraints.py` arguments and the corpus.

#### 55. `docs/reference/conformance.md` (Modify)

*   **Phase**: 4
*   **Type / Scope**: Documentation
*   **Proposed Changes**: Add the suite `ins-ui-constraints` (regenerated by `fieldseal conformance matrix`; a test fails when it is stale).

#### 56. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 4
*   **Type / Scope**: Specification
*   **Proposed Changes**: Amend INS-255 to name the files `tests/constraints/scenarios.json` and the golden survey, and to say that a feature adds its scenarios in the phase that adds its constraint. Amend INS-256 to say which of the cases apply to each row.

**Phase 5: Probes and the `.probes` item (#27, second half of #31)**

#### 57. `crates/kernel/src/schema.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Compact-dialect schema tables (kernel)
*   **Proposed Changes**: Add `probes` to `QUESTION_COMMON`: a dictionary from probe id to text (`Ty::Dict(&TEXT)`), doc "Approved follow-up questions for the collector, by stable id." Probe ids follow the slug rule of `compact::slug` and are checked in the expansion (below), not here. Add `probes` to the reserved question-key list in the `survey.question.*` shapes of every type.

#### 58. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Compact-dialect expansion
*   **Proposed Changes**: In `Survey::question` (after the `help` and `guidance` loop, line 727) expand `probes: {<id>: <text>}` into the canonical `probes: [{id, text}]`, in the order written, with the localised text keyed `<full path>.probes.<id>`. A probe id that is not a slug, or is repeated, is an error at `<question>/probes/<id>` (INS-262). A question named `probes`, `probe`, `extensions` or `base` is an error (INS-276); `index` (line 495) checks every id it records.

#### 59. `crates/adapters/authoring/src/survey.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Authoring: resolver and translation report
*   **Proposed Changes**: `report` (line 553) classifies a missing or stale entry whose `msgctxt` has a `.probes.<id>` part as an error (`FindingKind::MissingProbeTranslation`, INS-263), where every other missing or stale text stays a warning (INS-260). `SurveyRef::load` (line 463) returns these through `strict()` unconditionally, not only under `--strict`.

#### 60. `crates/apps/cli/src/survey_cmd.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: CLI: survey check
*   **Proposed Changes**: `resolve_errors` (line 114) prints a probe translation finding as an error even when `soft` is set, with the id INS-263 and the `msgctxt` in the message, so `survey check` exits 1 for it.

#### 61. `crates/contexts/instrument/src/domain/element.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: authored question
*   **Proposed Changes**: Add `pub struct Probe { pub id: String, pub text: LocalisedText }` and `Question.probes: Vec<Probe>` (after `guidance`, line 148). Doc: collector-only follow-ups (INS-262).

#### 62. `crates/contexts/instrument/src/application/decode.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: decoder
*   **Proposed Changes**: `question` (line 869): add `probes` to the allowed keys (line 874); read it as an array of closed objects `{id, text}` (`id` a path segment by INS-012, unique in the question, `text` localised with the same variables as `label`, INS-047, INS-084). An unknown key inside a probe is `INS-262`. The canonical field is emitted only when used.

#### 63. `crates/contexts/instrument/src/domain/compiled.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: compiled question
*   **Proposed Changes**: `QuestionNode` gains `probes: Vec<Probe>` (after `guidance`, line 69). `QuestionOrigin` gains `Annotation(Annotation)` (line 42), the first origin that Phase 2's module serves with a node: the synthesised `<path>.probes` question. Update the `Debug` outline writer at line 491 so the compiled outline names it.

#### 64. `crates/contexts/instrument/src/domain/compile.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: compiler
*   **Proposed Changes**: `question` (line 320) copies `probes` into the node and, when there are any, adds a second node at `annotation::item_path(path, Probes)` after the `other` node (line 358 to 376): a `codes` question with an inline code list made of the probe ids, `optional: true`, no nonresponse, `origin: Annotation(Probes)`, and no `when` of its own (it follows the visibility of its parent through the rule evaluation, as `.other` does). `check_question` (line 391) rejects probes on a `self` or `both` survey with INS-264 and, in a repeat, resolves the probe text variables as `label` does. Hierarchy, verify and overlay checks join this function in Phases 6, 7 and 12.

#### 65. `crates/contexts/instrument/src/domain/evaluation.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: evaluation
*   **Proposed Changes**: `Reader` (line 338) reads `<path>.probes` as a `codes` value whose list is the question's probe ids; an id outside the list is a value problem (INS-081). Setting the base value leaves the probe set; clearing or hiding the base clears it (the per-kind rule of `annotation::fold`). The synthesised item is never counted as unanswered and is not reported as unknown by `WIRE-051`.

#### 66. `crates/contexts/instrument/src/domain/annotation.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: annotation items
*   **Proposed Changes**: `Annotation::Probes` is now served: `data_type()` returns `codes`, and `split` recognises `<path>.probes` only when the base question lists probes (otherwise a path ending in `.probes` is an unknown item path, WIRE-051).

#### 67. `crates/contexts/instrument/src/application/render.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: render plan builder
*   **Proposed Changes**: `question` (line 270 to 303) fills `PlanQuestion.probes` from the node, in the interview's language, with the same text and variable handling as `label` (`self.text`). With `self_admin` the list is empty (the compile error already prevents probes there). The default layout builder skips nodes whose origin is `Annotation(_)`, like it treats other synthesised nodes, so no question is drawn for `.probes`.

#### 68. `crates/contexts/instrument/src/domain/render_plan.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: render plan
*   **Proposed Changes**: Add `pub struct PlanProbe { pub id: String, pub text: PlanText }` and `PlanQuestion.probes: Vec<PlanProbe>` (line 291). The plan writer (line 778 to 780) emits `probes` only when the list is not empty, so every existing golden plan stays byte-identical.

#### 69. `crates/contexts/instrument/src/application/layout.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Format core: layout validation
*   **Proposed Changes**: Line 179 and lines 596 to 604 treat `OtherText` nodes as not placeable and not reportable as unplaced. Treat `Annotation(_)` nodes the same way, so a layout neither has to place nor may place `<path>.probes`.

#### 70. `crates/contexts/instrument/src/application/lint.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Advisory lints
*   **Proposed Changes**: The lint that fires for an interviewer question with no `guidance` (line 168 area) also says that probes can be declared. Advisory, once per question. Add a lint when a question lists probes and its `label` is heading-like (INS-278), because probes follow the words read aloud.

#### 71. `crates/contexts/intake/src/landing.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Intake: landing
*   **Proposed Changes**: A `<path>.probes` value now has a compiled node (`QuestionOrigin::Annotation`), so the value-row builder (line 229) lands it as an observation with value type `codes`, like any other `codes` item, instead of skipping it as an unknown sibling. `apply` (line 100) applies `Annotation::on_value_set`: `Keep` for probes, `Replace` for the unit. A probe set whose base value is retracted or hidden is removed.

#### 72. `crates/contexts/collection/src/domain/capture.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Collection: pending capture
*   **Proposed Changes**: `editable` (line 313) accepts `<path>.probes` when its base question is editable and visible. `set_value` of the base keeps the probe set; `clear_value` removes it (COL-111, Phase 2).

#### 73. `crates/apps/cli/src/conformance_cmd/ins_probes.rs` (Create)

*   **Phase**: 5
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: Suite `ins-probes`. Checks for INS-262 (stable unique ids, canonical form emitted only when used, probe text variables in a repeat), INS-263 (a probe missing or stale in one declared language is an error and names the `msgctxt`), INS-264 (refused on `self` and `both`), INS-266 (the synthesised `.probes` node, its type, its fold rule, landing with value type `codes`), INS-276 (reserved words) and the golden-plan check that a question without probes plans byte-identically.

#### 74. `crates/apps/cli/src/conformance_cmd/strict_schema.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Strict-schema corpus table
*   **Proposed Changes**: One line for each new corpus file below, as `tests/schema-corpus/README.md` requires.

#### 75. `tests/schema-corpus/survey/type-probes.yaml` (Create)

*   **Phase**: 5
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: `probes` given as a list: `TypeMismatch` at `/sections/…/probes`.

#### 76. `tests/schema-corpus/survey/unknown-probe-for-its-type.yaml` (Create)

*   **Phase**: 5
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: A `probes` key on a `roster` question, whose shape does not allow it: `UnknownField`.

#### 77. `crates/adapters/authoring/tests/po_entries.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Authoring tests
*   **Proposed Changes**: Add `ins_262_a_probe_context_is_the_question_path_dot_probes_dot_id` (the context `instrument/meals.breakfast.probes.which-meal` passes `check_context`).

#### 78. `crates/adapters/authoring/tests/translation_report.rs` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Authoring tests
*   **Proposed Changes**: Add `ins_263_a_stale_or_missing_probe_translation_is_an_error_where_other_texts_warn`.

#### 79. `tests/constraints/surveys/constraints-corpus/instrument.yaml` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Shared corpus: golden instrument
*   **Proposed Changes**: Add an interviewer question with three probes. Probes are an aid, not a constraint; their scenarios (`kind: aid`) are played by the HTML and web harnesses in Phase 9.

#### 80. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-262 (a question MAY list `probes: [{id, text}]`; ids are stable slugs unique within the question, pinned like codes; the text is localised and may use the label's variables; probes are shown only to the collector), INS-263 (a probe missing or stale in a declared language MUST fail validation of the authoring folder; there is no fallback to the source language), INS-264 (probes MUST be rejected when `administration` is `self` or `both`, until the mode is recorded per capture), INS-266 (the synthesised item `<path>.probes` of type `codes` holds the probe ids used; it is self-reported by the collector; an empty set means none recorded) and INS-276 (the path segments `probes`, `probe`, `extensions` and `base` are reserved; amends INS-012). Amend INS-150 and INS-151: `label` is the exact words read aloud in an interviewer survey, and probes follow the same rule as `guidance`.

#### 81. `docs/reference/survey-folder.md` (Modify)

*   **Phase**: 5
*   **Type / Scope**: Reference
*   **Proposed Changes**: Add the probe translation key (`instrument/<path>.probes.<id>`) to the key grammar and the `probe-translation` finding (INS-263, error) to the findings table.

**Phase 6: Hierarchical code lists, broad answers and `within()`**

#### 82. `crates/kernel/src/schema.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Compact-dialect schema tables (kernel)
*   **Proposed Changes**: `survey.item` (line 867): add `parent` (text, a code of the same list). `survey.question.choice` (line 944): add `broad-answer` (`Ty::Enum(&["allowed"])`). `survey.condition` (line 1006): add `under` (`Ty::List(&LITERAL)`, cross-check "two operands: a question and a code").

#### 83. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Compact-dialect expansion
*   **Proposed Changes**: `list` (line 430): read `parent` on an item and emit it; a `parent` that names no code of the same list, or itself, is an error at the item (INS-267). Forms that cannot carry a parent (the inline label form, `scales`) are unchanged. `question` (line 712): `broad-answer: allowed` on `choice` and `choices` becomes the canonical control field `broadAnswer: allowed`. `condition` (line 958): `under: [question, code]` becomes the rule text `within($path, "code")` through `operand` and `literal_or_operand`; the operator list in the error message (line 987) names it.

#### 84. `crates/contexts/instrument/src/domain/codes.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: code lists
*   **Proposed Changes**: `Code` gains `parent: Option<String>` (after `exclusive`, line 62). `CodeList` gains the pure helpers `children(&self, code) -> Vec<&Code>`, `is_parent(&self, code) -> bool`, `chain(&self, code) -> Vec<&str>` (the code, then its parent, up to the root; never loops because a cycle is a compile error) and `depth(&self, code) -> usize`. They are the only code that walks the hierarchy.

#### 85. `crates/contexts/instrument/src/domain/control.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: controls
*   **Proposed Changes**: `Control::Choice` and `Control::MultiChoice` gain `broad_answer: bool`. `constraint_kinds` (Phase 3) adds `BroadAnswer` when a question's list has any parent and `AncestorExclusion` for a multi-choice over such a list. `ConstraintKind` (in `constraints.rs`) gains the two variants.

#### 86. `crates/contexts/instrument/src/domain/constraints.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: constraint kinds
*   **Proposed Changes**: Add `BroadAnswer` (parent codes are headings unless the question allows them) and `AncestorExclusion` (an ancestor and its descendant are not selected together, like INS-133). Update `ALL`.

#### 87. `crates/contexts/instrument/src/application/decode.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: decoder
*   **Proposed Changes**: `codes` (line 630): allow `parent` on a code (INS-267). `control` (line 1115): allow `broadAnswer` on `choice` and `multi-choice` with the single value `allowed`, and refuse it on every other control. The canonical fields are emitted only when used.

#### 88. `crates/contexts/instrument/src/domain/compile.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: compiler
*   **Proposed Changes**: `check_question` (line 391) and the code-list pass: a `parent` must name a code of the same list; the forest has no cycle and is at most 8 deep (INS-267, like INS-242); `exclusive` or `value` on a parent code is an error (INS-132, INS-133); a hierarchy on a `scale` or an `ordered` list is an error (INS-135); the `other` code has no parent and no children. `group` (line 202, the repeat expansion at line 209 to 215) refuses a repeat over a list that has parents (INS-126). A `broadAnswer` on a list with no parent is an error (INS-268). `type_check` (line 698) types `within`: its first argument is a coded path, its second a literal that is a code of that path's list (otherwise `INS-269`).

#### 89. `crates/contexts/instrument/src/domain/rules/ast.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: rule language
*   **Proposed Changes**: Add `Function::Within` with name `within` to `from_name` and `name` (lines 44 to 76), arity two.

#### 90. `crates/contexts/instrument/src/domain/rules/check.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: rule type check
*   **Proposed Changes**: `call` (line 317): `within(path, "code")` has type boolean when the path is a `choice` or `multi-choice` item; any other first argument is a type error (INS-269).

#### 91. `crates/contexts/instrument/src/domain/rules/eval.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: rule evaluation
*   **Proposed Changes**: `Slot` (line 49) gains `chains: Vec<Vec<String>>`, one chain per code the item holds (the code, then its ancestors). `call` (line 244) evaluates `Function::Within`: unset when the item is unset, otherwise true when any held chain contains the code. `==`, `!=` and `in` are not touched, so existing records replay identically (INT-012). Evaluation cost stays one node per call (INS-044).

#### 92. `crates/contexts/instrument/src/domain/evaluation.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: evaluation
*   **Proposed Changes**: `Reader::list` (line 521) returns a borrowed `&CodeList` instead of cloning the whole list on every call; `set_value` evaluates twice (`capture.rs:331`, `341`), so the clone was paid twice for every tap (brief, §3 performance). `code` (line 528) refuses a parent code in a question without `broadAnswer: allowed` with a value problem (INS-268). The seven `Slot` literals at lines 263, 362, 381, 405, 410, 415 and 518 get `chains` (empty unless coded); the two coded ones (405, 415) fill it from `CodeList::chain`. A multi-choice that holds a code and its ancestor is a value problem (INS-270); `max` counts selected codes.

#### 93. `crates/contexts/instrument/src/application/render.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: render plan builder
*   **Proposed Changes**: `control` (line 204) fills `PlanOption.parent` and `PlanOption.selectable` (a parent code is selectable only when the question allows broad answers) and `broad_answer` on `PlanControl::Choice` and `MultiChoice`. Children stay in list order under their parent.

#### 94. `crates/contexts/instrument/src/domain/render_plan.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: render plan
*   **Proposed Changes**: `PlanOption` (line 97) gains `parent: Option<String>` and `selectable: bool`; `PlanControl::Choice` and `MultiChoice` (line 129) gain `broad_answer: bool`. The writer emits the three only when the list has a parent, so existing golden plans do not change.

#### 95. `crates/contexts/instrument/src/application/lint.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Advisory lints
*   **Proposed Changes**: INS-271: warn when `eq`, `ne` or `in` compares with a code that has a selectable ancestor in a question that allows broad answers (the rule misses a broad answer; suggest `within`); warn when a code's `parent` and its concept's parent disagree (INS-242); extend the sentinel lint of INS-143 (line 17) to code labels such as "don't know which" and "not specified" under a parent. Advisory.

#### 96. `crates/contexts/instrument/src/domain/field_checks.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: field checks
*   **Proposed Changes**: Documentation only: state in the module comment that `duplicates` and `straightlining` compare codes exactly and so treat a parent and its child as different answers. No behaviour change; a check in `ins_hierarchy.rs` pins it.

#### 97. `crates/contexts/instrument/src/application/layout.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Format core: layout validation
*   **Proposed Changes**: Add `broadAnswer` to the control keys a layout may not override (the list at line 44).

#### 98. `crates/contexts/instrument/tests/vectors/rules.json` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Rule golden vectors
*   **Proposed Changes**: Add vectors for `within`: a code, its child, its grandchild, an unrelated code, an unset item, a multi-choice with one matching code, and `==` on the parent with a child held (false).

#### 99. `crates/apps/cli/src/conformance_cmd/rules.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Conformance: rule vectors
*   **Proposed Changes**: Run the new vectors in suites `ins-rules` and `ins-eval`; the scope's slots carry `chains` (line 12 to 25).

#### 100. `crates/apps/cli/src/conformance_cmd/ins_hierarchy.rs` (Create)

*   **Phase**: 6
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: Suite `ins-hierarchy`: INS-267 (every refused combination of the brief: cycle, depth 9, parent in another list, `exclusive`, `value`, scale, repeat, `other`), INS-268 (a parent code is refused unless `broad-answer: allowed`; with it, it is a value), INS-269 (`within` typing and result, `eq` stays exact), INS-270 (ancestor with descendant refused in a multi-choice; `max` counts codes), INS-271 (the lints), and that a broad answer is a value, not a nonresponse (`dont-know` stays separate).

#### 101. `crates/apps/cli/src/conformance_cmd/strict_schema.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Strict-schema corpus table
*   **Proposed Changes**: One line for each new corpus file below.

#### 102. `tests/schema-corpus/survey/enum-broad-answer.yaml` (Create)

*   **Phase**: 6
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: `broad-answer: maybe`: `EnumValue`.

#### 103. `tests/schema-corpus/survey/type-parent.yaml` (Create)

*   **Phase**: 6
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: `parent` given as a number: `TypeMismatch`.

#### 104. `tests/schema-corpus/survey/unknown-under-for-roster.yaml` (Create)

*   **Phase**: 6
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: A condition with `under` and a second operator: the single-operator rule of `survey.condition` is violated (`UnknownField` at the extra key).

#### 105. `tests/constraints/surveys/constraints-corpus/instrument.yaml` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Shared corpus: golden instrument
*   **Proposed Changes**: Add a food list with parents, one `choice` question with `broad-answer: allowed`, one without, and a `choices` question over the same list.

#### 106. `tests/constraints/scenarios.json` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Shared corpus: scenarios
*   **Proposed Changes**: Add the scenarios for `broad-answer` (a parent code is refused without the opt-in and accepted with it, by tap and by programmatic set) and `ancestor-exclusion` (selecting a child deselects or refuses its ancestor, as the exclusive code does), first collection and resurvey.

#### 107. `crates/adapters/web/src/device.rs` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Web device host
*   **Proposed Changes**: `WebCatalogue` does not list `BroadAnswer` or `AncestorExclusion` until Phase 9 delivers them, so this phase's instruments with parents are refused by the web device at import (INS-254) until then. The web device is not shipped between the phases.

#### 108. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 6
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-267 (a code MAY name a `parent` code of the same list; the hierarchy is a forest at most 8 deep with no cycle; moving a code to another parent changes its meaning, INS-136; the combinations that are errors), INS-268 (a `choice` or `multi-choice` question accepts a parent code only if it declares `broad-answer: allowed`; otherwise parent codes are group headings; a broad answer is a value, not a nonresponse), INS-269 (`within(path, code)` is true for the code or any descendant; `==`, `!=` and `in` stay exact), INS-270 (in a multi-choice a code and its ancestor MUST NOT both be selected; entry refuses it like INS-133) and INS-271 (lints for leaf comparisons over a broad question, parent and concept disagreement, and sentinel-like labels). Amend INS-131 to INS-137 (hierarchy interactions), INS-228 (a code `parent` is an answer at a coarser level, never rolled up; a `concept` is an unevaluated classification) and INS-040 to INS-048 (the function table gains `within`).

**Phase 7: Verified entry in the core**

#### 109. `crates/kernel/src/schema.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Compact-dialect schema tables (kernel)
*   **Proposed Changes**: Add `verify` to `QUESTION_COMMON`: `Ty::OneOf(&[Ty::Enum(&["retype", "read-back"]), Ty::Map(ShapeId("survey.verify"))])`, with a new closed shape `survey.verify` (`kind`: enum, required; `when`: `CONDITION`). The per-type rules (which types accept which kind) are cross-checked in the compiler, not in the shape, because they depend on the survey's administration.

#### 110. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Compact-dialect expansion
*   **Proposed Changes**: `question` (line 712): `verify: retype|read-back` or `verify: {kind, when}` becomes the canonical `verify: {kind, when?}`; `when` goes through `condition` (line 958) with the question's repeat scope.

#### 111. `crates/contexts/instrument/src/domain/element.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Format core: authored question
*   **Proposed Changes**: Add `pub enum VerifyKind { Retype, ReadBack }`, `pub struct Verify { kind, when: Option<Condition> }` and `Question.verify: Option<Verify>`.

#### 112. `crates/contexts/instrument/src/application/decode.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Format core: decoder
*   **Proposed Changes**: `question`: allow `verify` (a closed object `{kind, when}`); `when` is parsed as a condition like `when` on a question (INS-124).

#### 113. `crates/contexts/instrument/src/domain/compiled.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Format core: compiled question
*   **Proposed Changes**: `QuestionNode.verify: Option<CompiledVerify>` with the `when` resolved to a scoped expression.

#### 114. `crates/contexts/instrument/src/domain/compile.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Format core: compiler
*   **Proposed Changes**: `check_question`: `retype` only on `number`, `money`, `text` and `date` questions; `read-back` only on `choice` and `multi-choice` questions of an `interviewer` survey; both refused on `measurement-pair`, `stepper`, `roster`, `scale` and photo questions, and `read-back` refused on `self` and `both` (INS-272). The `when` is resolved with `resolve` (line 150) and compiled with the question's other expressions.

#### 115. `crates/contexts/instrument/src/domain/constraints.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Format core: constraint kinds
*   **Proposed Changes**: Add `VerifyRetype` and `VerifyReadBack`; `constraint_kinds` returns them for questions with `verify`. Update `ALL`.

#### 116. `crates/contexts/instrument/src/domain/evaluation.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Format core: evaluation
*   **Proposed Changes**: `Evaluation` gains `verify_required: BTreeSet<String>`: the verify items whose question is visible, whose `when` (if any) is true and whose value is a real value (a nonresponse needs no verification, INS-273). It is a pure function of the values, so every caller computes the same set. The capture combines it with its own verified set; the evaluator does not know what was verified.

#### 117. `crates/contexts/collection/src/domain/capture.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Collection: pending capture
*   **Proposed Changes**: `Capture` gains `verified: BTreeSet<String>` and `mismatches: BTreeMap<String, u8>` (not persisted, not sealed). New methods: `set_retyped(instrument, path, first, second)` (compares the two entries as canonical values, text after NFC, WIRE-004; on a match writes the value and marks it verified; on a mismatch writes nothing, keeps the earlier value, counts the miss and returns `CaptureError::VerifyMismatch { path, attempts }`, whose `offer_nonresponse` is true from the second miss), `confirm_read_back(instrument, path)` (marks the current value verified; refused when the item is not a `read-back` item or has no value), and `verify_state(path) -> VerifyState { NotRequired, Pending, Verified }`. `set_value` and `clear_value` remove the path from `verified`. `new` (line 188) marks every baseline value as verified, so values carried over in a resurvey or correction need nothing (INS-275). `readiness` (line 392) adds each required, unverified path to the hard list as `<path> (INS-275)` before the soft check; with `pause` it instead leaves those values out of `content` (line 413), so the first entry and unverified values are never written, even on pause (INS-273).

#### 118. `crates/contexts/collection/src/application/capture.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Collection: runtime API
*   **Proposed Changes**: `Runtime::set_retyped(path, first, second)` and `Runtime::confirm_read_back(path)` next to `set_value` (line 235), through `with_capture`. Both map the new `CaptureError` variants to `CollectionError::VerifyMismatch` and `CollectionError::NotVerifiable`.

#### 119. `crates/contexts/instrument/src/application/lint.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Advisory lints
*   **Proposed Changes**: Advice when an instrument declares `verify` on more than a few questions in one survey (collector fatigue; the count is a lint threshold with a default of 3), and when `verify` is set on a question that already has a range constraint that would catch the same error.

#### 120. `crates/apps/cli/src/conformance_cmd/ins_verify.rs` (Create)

*   **Phase**: 7
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: Suite `ins-verify`: INS-272 (the allowed and refused types and administrations), `when` limiting verification, `verify_required` for nonresponse, hidden and `when`-false items.

#### 121. `crates/apps/cli/src/conformance_cmd/col.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Collection conformance checks
*   **Proposed Changes**: Suite `col-verify`: COL-112 (the gate): a retype value written by `set_value` cannot be sealed; `set_retyped` with equal entries seals; a mismatch writes nothing and keeps the earlier value; the second mismatch offers nonresponse; nonresponse seals; a pause leaves out an unverified value and never writes a first entry; a resurvey that does not touch a verified value needs nothing; changing the value after verification requires verification again; NFC-equal text matches; read-back is confirmed by `confirm_read_back` only.

#### 122. `crates/apps/cli/src/conformance_cmd/strict_schema.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Strict-schema corpus table
*   **Proposed Changes**: One line for each new corpus file below.

#### 123. `tests/schema-corpus/survey/enum-verify.yaml` (Create)

*   **Phase**: 7
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: `verify: twice`: `EnumValue`.

#### 124. `tests/schema-corpus/survey/unknown-verify-key.yaml` (Create)

*   **Phase**: 7
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: `verify: {kind: retype, unless: …}`: `UnknownField` at `unless`.

#### 125. `tests/constraints/surveys/constraints-corpus/instrument.yaml` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Shared corpus: golden instrument
*   **Proposed Changes**: Add a `text` question with `verify: retype`, a `number` with `verify: {kind: retype, when: …}` and a `choice` with `verify: read-back`.

#### 126. `tests/constraints/scenarios.json` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Shared corpus: scenarios
*   **Proposed Changes**: Add retype scenarios (match, mismatch, second mismatch, paste into the second field refused, programmatic set of the second field refused, first entry visible nowhere in the pending record, pause) and read-back scenarios (one tap confirms, hold is not offered), for first collection and resurvey (INS-256).

#### 127. `crates/apps/cli/src/device.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: CLI: device simulator
*   **Proposed Changes**: The scenario runner (`set:` at line 400 and the nonresponse form at line 416) gains two step keys: `retype: {path: value}` (calls `Runtime::set_retyped` with the value twice, or with `first` and `second` when a mismatch is scripted) and `verify: [path]` (read-back confirmations). A `set:` of a verify item is accepted but the scenario's `seal` then reports the block, which is the behaviour a test wants. The embedded scenario help (line 15) and `--json` output name both.

#### 128. `crates/adapters/web/src/device.rs` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Web device host
*   **Proposed Changes**: `WebCatalogue` still omits the verify kinds until Phase 9.

#### 129. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-272 (`verify: retype|read-back`, where each is allowed, optional `when`), INS-273 (retype: the first entry is UI state only and never written, not on pause; the second is typed without the first visible, paste, autofill and IME suggestions off; equality after locale normalisation and NFC; match writes; mismatch discards both entries and keeps the earlier value; after the second mismatch the UI offers nonresponse or a reason), INS-274 (read-back: shown inline per question with "Read this back to the respondent", confirmed with one tap, never hold-to-confirm; the guidance says that the collector, not the device, speaks) and INS-275 (a verify item set or changed in this capture and not verified is a value problem that blocks sealing; nonresponse and carried-over values are exempt; nothing about verification is stored). Amend INS-252 (table rows for the two kinds), INS-164 and INS-253.

#### 130. `docs/reference/spec/collection.md` (Modify)

*   **Phase**: 7
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add COL-112: the capture MUST refuse to seal a verify item that is required and unverified, MUST NOT write a first entry, and on pause MUST leave unverified values out of the sealed content.

**Phase 8: Intake contract, codebook and export 1.1.0**

#### 131. `crates/contexts/intake/src/data_contract.rs` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Intake: data contract
*   **Proposed Changes**: `ContractCode` (line 69) gains `parent: Option<String>` and `is_leaf: bool`. `ContractItem` (line 108) gains `self_reported: bool`, `probes: Vec<ContractProbe>` (id and text in every language), `broad_answer: bool` and `verification: Option<&'static str>` (`retype` or `read-back`). `generate_data_contract` (line 278) fills them: an item with `Annotation(Probes)` origin is `self_reported` and its code list is the probe list; the `.probes` item's `description` says in plain words that the collector records it themselves and that an empty set means none recorded. `EXPORT_SCHEMA_VERSION` (line 65) becomes `1.1.0` (INT-085). `to_value` (line 540) emits the new keys only when they are set. No value is derived: `parent` is the code list's own field (INS-228, INT-083).

#### 132. `crates/adapters/landing-files/src/export/codebook.rs` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Results export: codebook
*   **Proposed Changes**: `CODEBOOK_HEADER` (line 22) gains `parent_code`, `is_leaf` and `self_reported`; `codebook_rows` (line 25) gives each code row its parent and leaf flag, and each probe a row of its own (item path `<path>.probes`, code = probe id, label = probe text in each language). Existing columns keep their order, so a reader of 1.0 columns still works (INT-085: a minor version only adds columns).

#### 133. `crates/adapters/landing-files/tests/export_readback.rs` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Export tests
*   **Proposed Changes**: Update the manifest and contract version assertions (lines 260 and 263) to `1.1.0`. Add `int_094_the_codebook_carries_parent_leaf_and_probe_rows` and `int_094_probe_rows_are_marked_self_reported_in_contract_and_codebook`. The long format is unchanged: `LONG_COLUMNS` still has 20 columns and `snapshot.rs` needs no migration.

#### 134. `crates/adapters/landing-files/tests/support/mod.rs` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Export test support
*   **Proposed Changes**: A published fixture instrument with a hierarchical list and a probed question, for the tests above.

#### 135. `crates/adapters/landing-files/tests/duckdb_recipe.rs` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Export tests
*   **Proposed Changes**: The recipe reads `codebook.csv` by header name; add the three columns to the expected header and assert that a query over 1.0 columns still runs.

#### 136. `tools/browser-tests/demo-e2e.py` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: Line 431 checks that the manifest names an export schema version; assert `1.1.0`.

#### 137. `docs/how-to/export-results-to-parquet.md` (Modify)

*   **Phase**: 8
*   **Type / Scope**: How-to
*   **Proposed Changes**: Describe the three codebook columns, say that the export version is 1.1.0 and that 1.0 readers keep working, and explain `.probes` rows (self-reported, an empty set means none recorded).

#### 138. `docs/reference/spec/intake.md` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INT-094 (the data contract and the codebook MUST carry each code's `parent` and leaf flag as unevaluated metadata, and MUST say that probe use is recorded by the collector and is not independently verified). Amend INT-085 (`EXPORT_SCHEMA_VERSION` 1.1.0 adds the codebook columns) and INT-071 (probe texts in every language). Phase 14 adds INT-095.

#### 139. `crates/contexts/intake/README.md` (Modify)

*   **Phase**: 8
*   **Type / Scope**: Documentation
*   **Proposed Changes**: Update the `data_contract` line: export version `1.1.0`, the new `ContractCode` and `ContractItem` fields.

**Phase 9: Web UI and HTML renderer**

#### 140. `crates/adapters/html/src/strings.rs` (Modify)

*   **Phase**: 9
*   **Type / Scope**: HTML renderer: platform text
*   **Proposed Changes**: New strings in English and Spanish, with the same fallback to English: the probe heading ("Approved follow-ups"), the broad-answer action ("Only knows: {category}"), "Type it again", "This answer is entered twice", the mismatch message, "Read this back to the respondent", the confirm label and the read-back confirmed state. The messages the renderer shows for a refusal go through `message.rs` (PLAT-050).

#### 141. `crates/adapters/html/src/message.rs` (Modify)

*   **Phase**: 9
*   **Type / Scope**: HTML renderer: catalogued messages
*   **Proposed Changes**: Add catalogued refusals: `verify-mismatch`, `verify-mismatch-again` (offers nonresponse), `paste-refused` and `ancestor-selected`.

#### 142. `crates/adapters/html/src/render.rs` (Modify)

*   **Phase**: 9
*   **Type / Scope**: HTML renderer
*   **Proposed Changes**: `question` (line 621): draw the probe chips after the label and guidance as buttons in a labelled group, each with `data-probe=<id>` and the text; tapping shows the text large enough to read aloud (a `<p>` with a larger class, `aria-live=polite`) and sets `<path>.probes`. `options` (line 1040): group child options under a heading for their parent; draw a parent as a heading, not an input, unless the question allows broad answers; then draw the broad-answer action after the probes, as a secondary button (`data-broad=<code>`). `control` (line 823): for a `verify` question add the second field (label "Type it again", `autocomplete=off`, `autocapitalize=off`, `spellcheck=false`, `data-verify=retype`) and an "entered twice" note before the first field (WEB-186); for `read-back` add the inline confirm button. `review` (line 1072) shows the probes used and the broad answer.

#### 143. `crates/adapters/html/src/page.js` (Modify)

*   **Phase**: 9
*   **Type / Scope**: HTML page script (input layer)
*   **Proposed Changes**: Enforce the new constraints in the page's own input layer (INS-253): the first retype entry stays in memory and in no attribute or `value` that `readQuestion` can see; the second field is blank, refuses `paste`, `drop` and `beforeinput` of `insertFromPaste`, compares after NFC and the locale parse of `canonical` (line 145), and on a match sets the question's value and marks it verified; on a mismatch clears both fields, keeps the earlier answer, announces the message in a `role=status` live region (WCAG 4.1.3) and, after the second miss, shows the nonresponse buttons. A parent option is not selectable unless `data-broad` allows it; in a multi-choice, selecting a code deselects its ancestors and descendants as the exclusive code does (line 60 area). The probe chips and the broad-answer action update `<path>.probes` and the value.

#### 144. `crates/adapters/html/src/page.css` (Modify)

*   **Phase**: 9
*   **Type / Scope**: HTML renderer: styles
*   **Proposed Changes**: Styles for the chip group, the read-aloud text, the second field, the confirm button and the group headings; 24 by 24 px targets and a 3:1 focus ring (INS-257).

#### 145. `crates/apps/web/assets/answers.js` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Web assets
*   **Proposed Changes**: `readQuestion` (line 14) ignores the retype helper field and a read-back that is not confirmed (they have no answer yet). `readAnswerEntries` (line 44) emits `<path>.probes` as a JSON array of the chips pressed. The two-number-input rule that reads a measurement pair (lines 28 to 33) is limited to `data-control=measurement-pair`, because a retype question holds two inputs that are not a pair.

#### 146. `crates/apps/web/assets/device.js` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Web assets
*   **Proposed Changes**: `sync` (line 735): a verify question's value is not sent through `setValues`; the page raises a `verified` event with the first and second entries and `sync` calls the new core methods (`setRetyped`, `confirmReadBack`), then shows the result. `blockedReason` (line 786) and `buildReview` (line 911) list unverified verify items with a link to the question. `answerText` (line 870) shows the broad answer with its category.

#### 147. `crates/apps/web/assets/instrument.js` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Web assets
*   **Proposed Changes**: The preview page evaluates `within` through the wasm `Workbench` and shows probes; it does not offer verification (it holds no capture).

#### 148. `crates/apps/web/assets/device.css` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Web assets
*   **Proposed Changes**: Layout of the verify controls and the blocked-seal list.

#### 149. `crates/adapters/web/src/device.rs` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Web device host
*   **Proposed Changes**: `WebCatalogue` now lists `BroadAnswer`, `AncestorExclusion`, `VerifyRetype` and `VerifyReadBack`, because this phase makes the page enforce them. A test in `tools/browser-tests/` fails if the list and the page disagree.

#### 150. `tests/constraints/scenarios.json` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Shared corpus: scenarios
*   **Proposed Changes**: Add `kind: aid` scenarios for probe chips (tap records the id, a second tap does not duplicate, clearing the answer clears the chips), the broad-answer action (shown after the probes, records the parent code) and the accessible names of the new controls.

#### 151. `tools/browser-tests/constraints.py` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: Play the new scenarios, including the live-region message, paste refusal and the second-field label, for both the rendered corpus page and the Device page.

#### 152. `tools/browser-tests/device-flow.js` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: `answerStep` fills a retype question by typing the same value into both fields, so the flow that ends in a seal still seals.

#### 153. `tools/browser-tests/wcag.sh` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: Render the constraints corpus page at compact and expanded window classes with the probe, hierarchy and verify controls in their open states, so axe and `wcag22.py` see them.

#### 154. `tools/browser-tests/wcag22.py` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: Target-size and focus-not-obscured checks include the chips, the broad-answer action and the confirm button.

#### 155. `crates/apps/web/tests/accessibility.rs` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Web tests
*   **Proposed Changes**: Add `ins_257_the_aid_controls_meet_the_wcag_checks` over the corpus page and `ins_257_the_second_field_has_its_own_label_and_a_live_region`.

#### 156. `crates/apps/web/tests/parity.rs` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Web tests
*   **Proposed Changes**: The preview-path and web-path bytes for the corpus survey are equal for every layout, language and window class.

#### 157. `docs/reference/spec/web-app.md` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add WEB-200 (probe chips), WEB-201 (the broad-answer action, shown after the probes, secondary to the control), WEB-202 (blind re-entry: its own label, no paste, no autofill, live-region mismatch, "entered twice" before the first entry) and WEB-203 (read-back: inline, one tap). Amend WEB-186 to list the new constraints. Record the WCAG 2.2 SC 3.3.7 (Redundant Entry) "essential" exception for blind re-entry in WEB-202.

#### 158. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 9
*   **Type / Scope**: Specification
*   **Proposed Changes**: Amend INS-257: the WCAG test list includes the aid controls. Add the accessibility sentence for SC 3.3.7 to INS-273.

**Phase 10: Bindings: wasm, UniFFI, Python**

#### 159. `crates/bindings/wasm/src/device.rs` (Modify)

*   **Phase**: 10
*   **Type / Scope**: wasm binding
*   **Proposed Changes**: Add exported methods next to `acknowledgeIncomplete` (line 272): `setRetyped(path, first, second)` and `confirmReadBack(path)`, each calling the `Runtime` method of Phase 7 and returning the same JSON view as `setValues`, and `constraintKinds()` returning the catalogue's kinds. Errors are converted by `js` (line 30) and carry the finding id. The render options gain nothing; probes and hierarchy are in the render plan already.

#### 160. `crates/adapters/web/src/device.rs` (Modify)

*   **Phase**: 10
*   **Type / Scope**: Web device host
*   **Proposed Changes**: Host-side `set_retyped` and `confirm_read_back` (next to `set_values`, line 646) call the Runtime and report problems the way `set_values` does.

#### 161. `crates/bindings/uniffi/src/lib.rs` (Modify)

*   **Phase**: 10
*   **Type / Scope**: UniFFI binding
*   **Proposed Changes**: Add `#[uniffi::export] fn constraint_kinds() -> Vec<String>` (the names of `ConstraintKind::ALL`) and a record `ConstraintSet` the native app fills to build its `ControlCatalogue`. The binding exports nothing else today (`core_version`, `runtime_profile`), and there is no render-plan export to extend, so the Android UI work (which does not exist, D13) starts from these two. `runtime_profile` is unchanged: the registration wire format (WIRE-130) is not touched.

#### 162. `crates/bindings/python/src/lib.rs` (Modify)

*   **Phase**: 10
*   **Type / Scope**: Python binding
*   **Proposed Changes**: Expose `constraint_kinds()` and the `within`-aware rule evaluation that the module already exports for rules, so the Python vector test keeps running the same Rust.

#### 163. `tools/test-python-vectors.sh` (Modify)

*   **Phase**: 10
*   **Type / Scope**: Test tool
*   **Proposed Changes**: Add the `within` vectors of Phase 6 to the Python run.

#### 164. `docs/reference/spec/platform-android.md` (Modify)

*   **Phase**: 10
*   **Type / Scope**: Specification
*   **Proposed Changes**: Name the probe, hierarchy and verification nodes and `constraint_kinds()` among what the native runtime must implement; no new requirement ids (the native UI does not exist).

#### 165. `docs/reference/spec/platform-profiles.md` (Modify)

*   **Phase**: 10
*   **Type / Scope**: Specification
*   **Proposed Changes**: Amend PLAT-067 and PLAT-068: a profile's UI test suite includes the scenarios of Phases 6, 7 and 9, and its control catalogue lists constraint kinds.

**Phase 11: ADR 0042 and the documentation of Part A**

#### 166. `docs/explanation/adr/0042-field-collection-aids.md` (Create)

*   **Phase**: 11
*   **Type / Scope**: ADR
*   **Proposed Changes**: Status Proposed, priority Must. Decides: amending schema 1.0 in place before the first release (D1) and how that squares with the Technical Plan's versioning rule; probes without a `script` field and the reserved name (D2, D12); the `.probes` sibling (D3, D5); that verification and category level are not stored (D4); hierarchy by `parent` with `broad-answer` and `within()` (D6, D8); verification semantics and read-back (D9, D10); administration mode (D11); platform scope and strict probe translation (D13). Records each counter-argument as a risk, the "Fieldseal never rolls up" rule as an amendment to INS-228, and that D7 (choice answers or food-frequency repeats) MUST be confirmed with collectors before the status becomes Accepted. Refines ADR 0032 and ADR 0037; depends on ADR 0034 and ADR 0041.

#### 167. `docs/explanation/adr/README.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: ADR index
*   **Proposed Changes**: Add the row for 0042.

#### 168. `docs/explanation/adr/0032-standard-survey-elements.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: ADR
*   **Proposed Changes**: Add "Amended by ADR 0042" for the text roles (probes) and code lists (parents).

#### 169. `docs/explanation/adr/0037-extensions-and-strict-schema-enforcement.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: ADR
*   **Proposed Changes**: Add "Amended by ADR 0042" for constraint kinds and entry enforcement of verification.

#### 170. `docs/explanation/adr/0040-compact-declarations-and-twelve-factor-config.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: ADR
*   **Proposed Changes**: List the new compact keys by pointing at `docs/reference/survey-dialect.md`, which is now the normative list; say that ADR 0040's list is historical.

#### 171. `docs/reference/spec/README.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: Specification index
*   **Proposed Changes**: Line 13 says breaking changes need a new `apiVersion`, while INS-090 versions the schema independently. Reconcile: a breaking change to a *released* schema needs a new major (INS-090); before the first release a schema version is amended in place (ADR 0042, WIRE-212).

#### 172. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: Specification
*   **Proposed Changes**: Amend INS-090 and INS-092 with the pre-release sentence above, and INS-228 as in Phase 6 if not already done. Update the document's open-questions list: D7 stays open until confirmed.

#### 173. `docs/reference/glossary.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: Glossary
*   **Proposed Changes**: Add: probe, broad answer, parent code, verified entry (retype, read-back), annotation item, collection aid. Add a collision note that a probe is not a service health probe, and that `verify` is not hold-to-confirm.

#### 174. `docs/tutorials/write-and-publish-your-first-survey.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: Tutorial
*   **Proposed Changes**: Add `short-label` and a real read-aloud `label` to the step that writes a question; add a short section on probes and `survey check` reporting a missing probe translation. Keep the tutorial's check commands runnable.

#### 175. `docs/index.md` (Modify)

*   **Phase**: 11
*   **Type / Scope**: Documentation index
*   **Proposed Changes**: Link the dialect reference and ADR 0042.

**Phase 12: Modification policy, overlay model and `survey check` (overlay)**

#### 176. `crates/kernel/src/schema.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Compact-dialect schema tables (kernel)
*   **Proposed Changes**: `DocKind` (line 38) gains `Overlay`, detected by a top-level `overlay` key (`detect`, line 52; `name`, line 69 returns `overlay`). `survey` gains `modification` (enum `locked|extend|modify`), `extension-points` (texts), `overlay-publishers` (texts), `translators` (texts) and `relaxes` (text). The section shape `survey.group` gains `extension-point` (text, the name of a point placed after the section). New shapes: `overlay` (closed: `overlay` {name, version} required, `base` required, `extend`, `language`, `title`, `description`, `purpose`, `publisher`, `copyright`, `translations`, `nonresponse`, `lists`, `scales`, `checks`), `overlay.id`, `overlay.base` (`name`, `version` required; `address` optional) and `overlay.extend` (a dictionary from point name to `Ty::Entries(&ELEMENT)`). `json_schema`, `paths`, `shapes_in` and `reference_markdown` learn the new kind. Covers INS-280, INS-281.

#### 177. `crates/adapters/authoring/src/compact.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Compact-dialect expansion
*   **Proposed Changes**: `Survey::expand` (line 297): emit `spec.modification`, `spec.extensionPoints`, `spec.overlayPublishers`, `spec.translators` and `spec.relaxes` when written; a section with `extension-point: <name>` emits an element `{kind: "extension-point", name}` after that section's group element at the same level, and the name must be in the survey's `extension-points` and a slug other than `end` (INS-280, INS-283). A new `overlay` entry point `expand_overlay(doc, texts)` reuses `elements`, `question`, `condition` and `check` to expand `extend:` into the canonical unresolved overlay document: `spec.base {name, version, address?}`, `spec.extensions {<point>: [elements…]}`, the overlay's own metadata and its language list. Added questions that name a list use the overlay's own `lists:` and `scales:` as inline options (`Options::Inline`) because the projection of §6 forbids any new top-level code list; an added question may not name a list of the base (INS-284). Added element paths are written relative to the slot; the resolver prefixes them (below).

#### 178. `crates/adapters/authoring/src/survey.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Authoring: survey folder resolver
*   **Proposed Changes**: `SurveyTree::survey` (line 278) accepts a folder with `overlay.yaml` instead of `instrument.yaml`; both together is the error `ambiguous-survey`, neither is `no-instrument` (CLI-045). `SurveyRef` gains `overlay: Option<PathBuf>`. `SurveyRef::load` (line 463) on an overlay returns `ResolveKind::BaseRequired` unless called through the new `load_overlay(&self, base: &BaseInput)`, where `BaseInput { canonical: Value, address: Option<String>, source: Option<SurveyRef> }`. `load_overlay` expands the overlay, derives the translation keys of inherited text from the base *source* with `expand_seen` (line 117 of `compact.rs`; this is the only place the `msgctxt` to text pointer mapping exists, and the canonical form has none), and calls `overlay::resolve` of the format core. A language-only overlay with no base source is `base-source-required`. `address` omitted in `overlay.yaml` is filled from `BaseInput.address` (see Decisions made while planning). Layouts of an overlay folder are read as for a survey and bound to the resolved instrument.

#### 179. `crates/contexts/instrument/src/domain/overlay.rs` (Create)

*   **Phase**: 12
*   **Type / Scope**: Format core: modification policy, overlay check and resolution
*   **Proposed Changes**: Pure functions over canonical `Value` trees (the form that is signed and bundled). `enum Modification { Locked, Extend, Modify }` with the order `Locked < Extend < Modify` used by the downgrade rule; `struct BasePolicy { modification, extension_points: BTreeSet<String>, overlay_publishers: Vec<KeyIdText>, translators: Vec<KeyIdText>, relaxes: Option<String> }`; `fn policy_of(doc: &Value) -> Result<BasePolicy, Findings>` (absent `modification` is `Modify`, INS-280); `fn base_ref(doc: &Value) -> Option<BaseRef>`; `fn kind_of(doc: &Value) -> OverlayKind { NotAnOverlay, Extending, LanguageOnly }`; `fn resolve(base: &Value, overlay: &Value, translations: &Translations) -> Result<Value, Findings>` (the base content, the added elements in `spec.extensions` slots, the overlay's metadata and `spec.base`, and added languages merged into every localised text; every base text must be translated into an added language or the result is an error); and `fn check(base: &Value, overlay: &Value) -> Findings`, the one comparison of §6: policy gate, placement (INS-283), projection and byte equality with the first differing path (INS-282), added rules and paths (INS-284) and the language-only case (INS-285). `check` returns findings only; it never decides who signed. Findings use the new kinds `OverlayBase`, `OverlayContent`, `OverlayPlacement`, `OverlayRule`. The module has no I/O and no dependency outside the crate (ADR 0028, `architecture.toml`).

#### 180. `crates/contexts/instrument/src/domain/finding.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Format core: findings
*   **Proposed Changes**: Add `FindingKind::OverlayBase`, `OverlayContent`, `OverlayPlacement`, `OverlayRule`; give each a stable lower-case name for the CLI and for the shared vectors (`overlay-base`, `overlay-content`, `overlay-placement`, `overlay-rule`).

#### 181. `crates/contexts/instrument/src/domain/mod.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Format core exports
*   **Proposed Changes**: `pub mod overlay;`.

#### 182. `crates/contexts/instrument/src/domain/element.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Format core: authored elements
*   **Proposed Changes**: `Element` gains `ExtensionPoint(String)`. It has no path, no label and no data; it only marks a place.

#### 183. `crates/contexts/instrument/src/domain/instrument.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Format core: instrument definition
*   **Proposed Changes**: `InstrumentDefinition` gains `modification: Modification`, `extension_points: Vec<String>`, `overlay_publishers: Vec<String>`, `translators: Vec<String>`, `relaxes: Option<String>`, `base: Option<BaseRef>` and `extensions: BTreeMap<String, Vec<Element>>`.

#### 184. `crates/contexts/instrument/src/application/decode.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Format core: decoder
*   **Proposed Changes**: `spec` allowed keys (line 338) gain `modification`, `extensionPoints`, `overlayPublishers`, `translators`, `relaxes`, `base` and `extensions`; `element` (line 846) accepts `{kind: extension-point, name}`; the policy keys are validated as in INS-280 and INS-286 (key ids are 32 hexadecimal characters, no duplicates). `base` and `extensions` are accepted only together.

#### 185. `crates/contexts/instrument/src/domain/compile.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Format core: compiler
*   **Proposed Changes**: `walk` (line 176) turns an `ExtensionPoint` marker into the elements of `spec.extensions[name]` at that place (and `end` after the last top-level element) with the path prefix `extensions.<point>`, so added paths never shadow a base path (INS-284). `check_question` refuses a question path that begins with the reserved segments (INS-276). Added group rules are compiled with their scope as for any group; the rule that they may not `skip` or `derive` a base path is checked in `overlay::check`, where base and added content can be told apart.

#### 186. `crates/contexts/instrument/src/application/validate.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Format core: validation
*   **Proposed Changes**: `validate_instrument` (line 17 area) rejects `modification` other than `modify` together with an unresolved overlay document (a document with `spec.extensions` and no `spec.base.address`), and an `extend` policy whose named point has no marker.

#### 187. `crates/apps/cli/src/survey_cmd.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: CLI: survey check
*   **Proposed Changes**: `check` (line 30) detects an overlay folder and takes two more flags, `--base <publication file>` (a `.published` file of the base: its canonical bytes and address) and `--base-source <survey folder>` (the base's source, for translation keys; its expansion must equal the publication's canonical bytes). It loads with `load_overlay`, runs `overlay::check` on the base and the resolved instrument, and prints the findings with the ids of INS-280 to INS-285, kind and path; an error finding gives exit 1. Without `--base` an overlay folder reports `base-required` (CLI-056). `survey list` (line 150) shows an overlay as `overlay of <base name> <version>`.

#### 188. `crates/apps/cli/src/schema_cmd.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: CLI: schema export
*   **Proposed Changes**: `kind_of` (line 28) accepts `overlay`; `SCHEMA_VERSION` stays `1.0.0`.

#### 189. `crates/apps/cli/src/new_cmd.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: CLI: new survey
*   **Proposed Changes**: `new overlay <name> --base <name>` scaffolds `overlay.yaml` with the schema header, an `end` slot and an `i18n` folder (CLI-056). The existing `new survey` is unchanged.

#### 190. `crates/apps/cli/src/conformance_cmd/ins_overlay.rs` (Create)

*   **Phase**: 12
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: Suite `ins-overlay`: one accepted and one refused case for each of the rules of §6 built in memory from a small base (steps 1 to 7), and the policy shape (INS-280): default `modify`, `extend` markers, unknown point names, `locked` with extensions. The full matrix with fixtures is Phase 16.

#### 191. `crates/apps/cli/src/conformance_cmd/strict_schema.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Strict-schema corpus table
*   **Proposed Changes**: Add the `overlay` kind and one line for each file below.

#### 192. `crates/apps/cli/tests/strict_schema_corpus.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: CLI tests
*   **Proposed Changes**: The corpus table check lists the `overlay` directory.

#### 193. `crates/adapters/authoring/tests/schema_differential.rs` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Authoring tests
*   **Proposed Changes**: Line 252: add `("overlay", DocKind::Overlay)` to the directories compared.

#### 194. `tests/schema-corpus/overlay/missing-base.yaml` (Create)

*   **Phase**: 12
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: An overlay with no `base`: `MissingField`.

#### 195. `tests/schema-corpus/overlay/unknown-field.yaml` (Create)

*   **Phase**: 12
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: An unknown top-level key: `UnknownField`.

#### 196. `tests/schema-corpus/overlay/type-extend.yaml` (Create)

*   **Phase**: 12
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: `extend` given as a list: `TypeMismatch`.

#### 197. `tests/schema-corpus/survey/enum-modification.yaml` (Create)

*   **Phase**: 12
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: `modification: frozen`: `EnumValue`.

#### 198. `tests/schema-corpus/README.md` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Strict-schema corpus
*   **Proposed Changes**: One directory per schema now includes `overlay/`.

#### 199. `docs/reference/survey-folder.md` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Reference
*   **Proposed Changes**: Add the overlay folder (`overlay.yaml`, `i18n/`, optional `layouts/`) to the table of homes, the flags of `survey check` for overlays, and the findings `ambiguous-survey`, `base-required`, `base-source-required`, `overlay-base`, `overlay-content`, `overlay-placement` and `overlay-rule` (INS-280 to INS-285).

#### 200. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-280 (`spec.modification` is `locked`, `extend` or `modify`, default `modify`; `extend` names extension points, `end` always exists; the policy is part of the canonical bytes), INS-281 (an overlay names a published base by `spec.base {name, version, address}` and adds elements in `spec.extensions` slots; the published instrument is the resolved one; one level only), INS-282 (the overlay check: after removing the slots, the overlay's own metadata and the languages the base does not declare, the canonical bytes equal the base's without its metadata; the first differing path is reported; aids added to a base question are therefore refused), INS-283 (content outside the base and the slots, or a slot for an undeclared point, is refused), INS-284 (added checks may read base answers but MUST NOT `skip` or `derive` a base path; added paths live under `extensions.<point>` and may not shadow a base path; added questions use inline lists) INS-285 (an overlay with no `extend` that only adds languages is a translation) and INS-286 (`translators` and `overlayPublishers` are lists of publisher key ids, 32 hexadecimal characters each, without duplicates). Amend INS-112: `derivedFrom` stays a citation; `spec.base` is the checked link. Amend INS-090: the new keys are additions.

#### 201. `docs/reference/spec/cli.md` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add CLI-056: `survey check` MUST check an overlay folder against its base (`--base`, `--base-source`) with the format core's `overlay::check` and exit 1 on any error finding; `new overlay` scaffolds one.

#### 202. `docs/reference/survey-dialect.md` (Modify)

*   **Phase**: 12
*   **Type / Scope**: Reference
*   **Proposed Changes**: Regenerated body: the policy keys, `extension-point`, and the `overlay` document.

**Phase 13: Authorisation and the four verifiers**

#### 203. `crates/contexts/publishing/src/domain/overlay.rs` (Create)

*   **Phase**: 13
*   **Type / Scope**: Publishing: overlay authorisation
*   **Proposed Changes**: Pure functions over verified publications. `fn verify_overlay(base: &Publication, overlay: &Publication, withdrawals: &[Withdrawal]) -> Findings`: decodes both canonical documents, runs `instrument::overlay::check`, then `authorise`; this is the one function all four verifiers call. `fn authorise(base: &Publication, overlay: &Publication, withdrawals) -> Findings`: the base is an instrument and its address equals `spec.base.address` (PUB-128); if the base lists `overlayPublishers`, an overlay with extensions carries a counted signature by one of them (PUB-129); a language-only overlay carries a counted signature by a `translators` key, or by one of the base's own publisher keys when the base has no `translators` and is `locked` or `extend` (PUB-130); with no `overlayPublishers` any publisher the trust bundle trusts may publish an overlay of a `modify` or `extend` base (D19); a base that is itself an overlay is refused (one level, INS-281); a withdrawn base refuses a *new* overlay or bundle but not an existing one (PUB-133). `fn check_downgrade(candidate: &Publication, earlier: &[Publication]) -> Findings` (PUB-131, PUB-132): the candidate's policy is no weaker than the strongest earlier version of the same name unless `relaxes` names an earlier address of that name; removing an extension point is tightening, adding one is relaxing. Callers verify the publications first (`VerifyPublication`); these functions do not check signatures, only whose they are. Publishing already depends on Instrument (`architecture.toml`), so no edge is added.

#### 204. `crates/contexts/publishing/src/domain/mod.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Publishing exports
*   **Proposed Changes**: `pub mod overlay;` and re-exports.

#### 205. `crates/contexts/publishing/src/domain/error.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Publishing errors
*   **Proposed Changes**: `PublishingError::OverlayRefused(Vec<String>)` for the callers that need an error value; the findings stay the primary form.

#### 206. `crates/apps/cli/src/conformance_cmd/publishing.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Publishing conformance checks
*   **Proposed Changes**: Units for PUB-128 to PUB-133 over small signed publications from the existing test keys (`crates/contexts/publishing/tests/common/mod.rs`): allow-lists listed and unlisted, the default translator rule, address mismatch, downgrade with and without `relaxes`, withdrawn base.

#### 207. `crates/contexts/publishing/tests/common/mod.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Publishing test support
*   **Proposed Changes**: Helpers that build a base and an overlay publication signed by named test keys.

#### 208. `crates/contexts/distribution/src/domain/content.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Distribution: bundle content
*   **Proposed Changes**: `BundleContent` (line 24) gains `bases: Vec<Publication>`: the bases of the overlays the bundle carries, for verification only. `to_value` (line 123) writes it as the optional list `bases` and leaves it out when empty, so existing bundles encode identically; `decode` (line 164) reads it with `list(&mut f, "bases", false, publication)` and rejects a duplicate address across `instruments` and `bases`; `manifest` (line 194) gains `bases: Vec<ContentAddress>`; `BundleManifest` (line 54) gains the field. A base that is not assigned is never offered for capture (the device lists only `instruments`).

#### 209. `crates/contexts/distribution/src/domain/error.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Distribution errors
*   **Proposed Changes**: `DistributionError::OverlayRefused { address, findings: Vec<String> }` and `BundleRejection::Overlay { address, findings }`; `bundle-failed` carries the first finding's kind as its reason code (`overlay-content`, `overlay-placement`, `overlay-rule`, `overlay-base`, `overlay-unauthorised`).

#### 210. `crates/contexts/distribution/src/application/build.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Distribution: factory build
*   **Proposed Changes**: After `fetch_all` of the instruments (line 235), `fetch_bases` reads the base of every instrument that has `spec.base` from the artefact registry by address (`p.artefacts.get`), requires it to be a published, verified, non-withdrawn instrument, calls `publishing::overlay::verify_overlay` and `check_downgrade` (the registry's `list(kind, name)` gives the earlier versions) and puts the bases into `BundleContent.bases`. A failure returns `OverlayRefused` and no bundle is sealed or signed (DIS-086).

#### 211. `crates/contexts/distribution/src/application/verify.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Distribution: bundle verification
*   **Proposed Changes**: Step 6 (artefacts, line 115 and 246): each publication in `bases` verifies with `VerifyPublication` like an instrument; every instrument with `spec.base` must have its base in `bases`; `verify_overlay` passes (DIS-087). A new public helper `verify_overlays(content, verifier) -> Result<(), BundleRejection>` is what `Collection` calls at every unlock (below). The header comment's step list names the new check.

#### 212. `crates/contexts/distribution/src/domain/facts.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Distribution: release facts
*   **Proposed Changes**: `check_composition` input (line 145 area) ignores `bases` for layouts and localisations (they apply to assigned instruments only).

#### 213. `crates/contexts/collection/src/application/bundle.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Collection: bundle import
*   **Proposed Changes**: `verify_bundle` (line 134) calls `publishing::overlay::verify_overlay` for the opened bundle's instrument against its base (the device verifies at import and at each unlock, PUB-073). A device holds exactly one instrument per bundle (`bundle_opener.rs:97`), which is the overlay; its base is held only to verify it. A failure is `CollectionError::OverlayRefused` and the previous bundle is kept (DIS-031).

#### 214. `crates/contexts/collection/src/domain/bundle.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Collection: opened bundle
*   **Proposed Changes**: `OpenedBundle` (line 108) gains `bases: Vec<Publication>`, not offered for capture.

#### 215. `crates/adapters/memory/src/bundle_opener.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: In-memory adapter: bundle opener
*   **Proposed Changes**: `open` (line 135) copies `content.bases` into `OpenedBundle.bases` after `VerifyBundle` has verified them. The one-instrument rule (line 97) applies to `instruments` only.

#### 216. `crates/adapters/memory/src/collection.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: In-memory adapter
*   **Proposed Changes**: The `OpenedBundle` literal (line 1019) gets `bases`.

#### 217. `crates/adapters/memory/src/conformance.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: In-memory adapter: contract runs
*   **Proposed Changes**: The `OpenedBundle` literal (line 339) gets `bases`.

#### 218. `crates/apps/factory/src/reconciler.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Factory app: reconciler
*   **Proposed Changes**: The mapping from a build error to a reason code (lines 377 and 669) maps `OverlayRefused` to the code of its first finding. The previous bundle stays, and the failure is recorded once per tenancy as for any other build failure.

#### 219. `crates/apps/factory/src/main.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Factory app
*   **Proposed Changes**: The `bundle-failed` event (line 262) carries `findings` (kind and path) next to `reason`.

#### 220. `crates/apps/factory/tests/reconciler.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Factory tests
*   **Proposed Changes**: Add `dis_086_an_overlay_that_fails_the_check_builds_no_bundle_and_the_old_bundle_stays`.

#### 221. `crates/apps/cli/src/artefact_kinds.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: CLI: kind validation
*   **Proposed Changes**: `KindCx` gains `base: Option<&Publication>`. `check_instrument` (line 101): a document with `spec.base` requires `cx.base` and runs `verify_overlay` on a draft publication of the document against it; findings become blocking diagnostics. A document without `spec.base` is unchanged.

#### 222. `crates/apps/cli/src/artefact_cmd.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: CLI: artefact
*   **Proposed Changes**: `provenance` (line 214) takes `--base <publication file>` for an overlay. `publish` (line 582) runs `check_downgrade` against the registry's earlier versions of an instrument of the same name before `put`, and `verify_overlay` for an overlay (PUB-128, PUB-131).

#### 223. `crates/apps/cli/src/bundle_cmd.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: CLI: bundle build
*   **Proposed Changes**: `bundle build` (line 283) accepts `--base <publication file>` (repeatable), which it passes to the builder as the registry content for the overlay's base.

#### 224. `crates/contexts/intake/src/ports.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Intake ports
*   **Proposed Changes**: `InstrumentSource` (line 97) gains `fn publication(&self, address: &ContentAddress) -> Result<Option<Publication>, InstrumentSourceError>`: the verified instrument publication at that address (an overlay or its base). Contract: returns only publications that verified (PUB), `None` otherwise.

#### 225. `crates/contexts/intake/src/contract.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Intake port contracts
*   **Proposed Changes**: `instrument_source_contract` (line 71) checks `publication` agrees with `instrument` for the known fingerprint and returns `None` for any other address.

#### 226. `crates/adapters/file/src/instruments.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: File adapter: instrument source
*   **Proposed Changes**: `PublishedInstruments` implements `publication` with the same directory scan and `VerifyPublication` as `instrument` (line 33), by address.

#### 227. `crates/adapters/memory/src/intake.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: In-memory adapter
*   **Proposed Changes**: `MemoryInstrumentSource` (line 113) implements `publication`.

#### 228. `crates/contexts/intake/src/gate/mod.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Intake: gate
*   **Proposed Changes**: `Instruments` (line 195) gains `refused: BTreeMap<Fingerprint, Vec<String>>`. `load_instruments` (line 274): for an instrument that has `spec.base`, fetch both publications through the new port method, run `verify_overlay`, and on findings store `None` in `by_fingerprint` and the finding texts in `refused`. Withdrawals are not consulted, so a base withdrawn after landing does not stop replay (PUB-133). The result is memoised per (overlay address, base address) pair for the life of the gate, because publications are immutable and the gate loads instruments again for every submission.

#### 229. `crates/contexts/intake/src/gate/replay.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Intake: replay
*   **Proposed Changes**: Line 108: a record whose instrument is in `refused` is held with `the record's instrument is an overlay that does not verify against its base (INT-093): <kind>`, not with the generic "not published" reason.

#### 230. `crates/apps/intake/tests/upload_flow.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Intake app tests
*   **Proposed Changes**: Add `int_093_records_of_an_unverified_overlay_are_held_with_their_own_reason`.

#### 231. `docs/reference/spec/publishing.md` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add PUB-128 to PUB-134. PUB-128: an overlay's base MUST be a published instrument whose publication verifies and whose address equals `spec.base.address`. PUB-129: if the base lists `overlayPublishers`, an overlay with extensions MUST carry a counted signature by a listed key. PUB-130: a language-only overlay MUST carry a counted signature by a `translators` key, or, with no list on a `locked` or `extend` base, by a key of the base's publisher. PUB-131: a base whose policy is weaker than the strongest earlier version of the same name in the artefact registry MUST be refused unless it names that version in `relaxes`. PUB-132: removing an extension point is tightening and needs no marker; adding one is relaxing and does. PUB-133: a withdrawn base MUST NOT be used for a new overlay or bundle, and existing overlays and landed data stay valid. PUB-134: `verify_overlay` MUST be the only implementation of the overlay check at every verifier. Amend PUB-104 to say why the downgrade check reads the registry and not the log.

#### 232. `docs/reference/spec/distribution.md` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add DIS-085 (a bundle MAY carry `bases`, for verification only; a base is never offered for capture), DIS-086 (the factory MUST refuse to build a bundle that holds an overlay failing `verify_overlay`; the failure is `bundle-failed` and the previous bundle stays) and DIS-087 (a runtime MUST reject a bundle whose overlay lacks its base or fails `verify_overlay`, and keeps its earlier bundle). Amend DIS-030 step 7 and DIS-010.

#### 233. `docs/reference/spec/wire-formats.md` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Specification
*   **Proposed Changes**: Amend WIRE-094 and the CDDL of `BundleContent` (line 352) with the optional `bases: [+ publication]`, left out when empty. Nothing else in the bundle changes.

#### 234. `docs/reference/spec/intake.md` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INT-093: intake MUST run `verify_overlay` when it learns an overlay instrument and for every replay (INT-012), and MUST hold the records of one that fails with that reason; the rule does not consult withdrawals. Amend INT-070 and the `ArtefactRegistry` row of the ports table (the new `publication` call).

#### 235. `docs/reference/spec/collection.md` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Specification
*   **Proposed Changes**: Amend COL-003/COL-005 text for import: overlay verification is part of it.

#### 236. `docs/reference/spec/trust.md` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Specification
*   **Proposed Changes**: One paragraph: the allow-lists name publisher key ids from the trust bundle and add no new key role.

#### 237. `crates/contexts/distribution/tests/vectors/overlay_bundle.json` (Create)

*   **Phase**: 13
*   **Type / Scope**: Distribution golden vector
*   **Proposed Changes**: A bundle plaintext with one overlay and its base in `bases`, encoded canonically, for `conformance run --suite distribution` (DIS-085, WIRE-094).

#### 238. `crates/apps/cli/src/conformance_cmd/distribution.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Distribution conformance checks
*   **Proposed Changes**: Run the new vector: decode, re-encode equal, `bases` left out when empty, duplicate address rejected.

#### 239. `crates/apps/security-tests/tests/bundle_attacks.rs` (Modify)

*   **Phase**: 13
*   **Type / Scope**: Security tests
*   **Proposed Changes**: Add `dis_087_a_bundle_with_a_forged_base_a_missing_base_or_a_downgraded_base_is_rejected` and the same for a tampered `bases` entry.

**Phase 14: Overlay lineage at intake**

#### 240. `crates/contexts/intake/src/data_contract.rs` (Modify)

*   **Phase**: 14
*   **Type / Scope**: Intake: data contract
*   **Proposed Changes**: `ContractItem` gains `lineage: Lineage` (`Inherited` or `Added`); `DataContract` gains `base_address: Option<String>` (from `spec.base.address`). An item is `Added` when its path starts with `extensions.`, else `Inherited`; code lists follow the items that use them (an inline list of an added question is added). `to_value` (line 540) emits `lineage` and `baseAddress` only for an overlay. A pure `fn inherited_columns_differ(a: &DataContract, b: &DataContract) -> Vec<String>` lists any inherited item whose path, value type, unit, code list codes (with parents and values), nonresponse set or conditionality differs; it is the check that a locked base's columns are identical across overlays (D16). It derives nothing (INT-083).

#### 241. `crates/adapters/landing-files/src/export/codebook.rs` (Modify)

*   **Phase**: 14
*   **Type / Scope**: Results export: codebook
*   **Proposed Changes**: `CODEBOOK_HEADER` gains `lineage` and `base_address` after the Phase 8 columns. Both are empty for an instrument that is not an overlay.

#### 242. `crates/adapters/landing-files/src/export/manifest.rs` (Modify)

*   **Phase**: 14
*   **Type / Scope**: Results export: manifest
*   **Proposed Changes**: Each entry of `instruments` (line 45) gains `base_address` when the instrument is an overlay.

#### 243. `crates/adapters/landing-files/src/export/mod.rs` (Modify)

*   **Phase**: 14
*   **Type / Scope**: Results export
*   **Proposed Changes**: `ExportTable` carries `base_addresses: BTreeMap<Fingerprint, ContentAddress>` from the contracts; `render_export` is otherwise unchanged. `LONG_COLUMNS` stays at 20 columns and the snapshot reader is not touched.

#### 244. `crates/adapters/landing-files/src/export/reader.rs` (Modify)

*   **Phase**: 14
*   **Type / Scope**: Results export: published reader
*   **Proposed Changes**: `Published::read` (line 34) also loads the bases of overlays from the published directory, verified like instruments, so a contract can name its base address and an export of an overlay does not fail with `NoPublication` for the base.

#### 245. `crates/adapters/landing-files/tests/export_readback.rs` (Modify)

*   **Phase**: 14
*   **Type / Scope**: Export tests
*   **Proposed Changes**: Add `int_095_inherited_columns_are_marked_with_the_base_address_and_added_columns_are_not` and `int_095_two_overlays_of_one_locked_base_have_identical_inherited_columns`. The export version stays `1.1.0` (the columns of Phases 8 and 14 are one unreleased minor).

#### 246. `crates/apps/cli/src/intake_cmd.rs` (Modify)

*   **Phase**: 14
*   **Type / Scope**: CLI: intake contract
*   **Proposed Changes**: `contract` (line 137) prints lineage and base address in the human summary and in `--json`.

#### 247. `docs/reference/spec/intake.md` (Modify)

*   **Phase**: 14
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INT-095: the data contract, the codebook and the manifest MUST mark every item of an overlay `inherited` (with the base address) or `added`; each overlay lands as its own instrument (INT-070); the long format and the snapshot reader are unchanged. Amend INT-071, INT-085.

#### 248. `docs/how-to/export-results-to-parquet.md` (Modify)

*   **Phase**: 14
*   **Type / Scope**: How-to
*   **Proposed Changes**: Add the pooling recipe: join `results` to `codebook` on instrument and item path, filter `lineage = 'inherited'` and one `base_address`.

**Phase 15: Licence and translation lint**

#### 249. `crates/contexts/instrument/src/application/lint.rs` (Modify)

*   **Phase**: 15
*   **Type / Scope**: Advisory lints
*   **Proposed Changes**: INS-287: a warning when the licence id in `copyright` contains the `ND` term (split on `-`) and the survey's policy is `modify` (declared) or absent; a warning when an `extend` or `locked` base has no `overlayPublishers` and no `translators` and an `-ND` licence (anyone trusted may attach content to it); advice on a language-only overlay that names the signer rule that will apply (`translators`, or the base's publisher). The licence never changes a policy or a verdict (D18).

#### 250. `crates/apps/cli/src/conformance_cmd/ins_overlay.rs` (Modify)

*   **Phase**: 15
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: Add INS-287 checks: `-ND` with `modify` warns, with `locked` does not, an unknown licence id does not; the lint never turns into an error under `--strict` (lint findings are advice).

#### 251. `crates/apps/cli/tests/survey_cli.rs` (Modify)

*   **Phase**: 15
*   **Type / Scope**: CLI tests
*   **Proposed Changes**: Add `ins_287_survey_check_warns_on_an_nd_licence_with_no_locking_policy`.

#### 252. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 15
*   **Type / Scope**: Specification
*   **Proposed Changes**: Add INS-287 (lint rules for licence and translation against the policy; advisory).

**Phase 16: Overlay fixtures and the four-verifier matrix**

#### 253. `crates/contexts/instrument/tests/overlay/README.md` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures
*   **Proposed Changes**: How the matrix works: each case names a base fixture, an overlay fixture, the signers, and the expected result; the four verifiers run the same file; how to add a case.

#### 254. `crates/contexts/instrument/tests/overlay/vectors.json` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: the shared vector file
*   **Proposed Changes**: One entry per case: `{id, rule, base, overlay, signers, base_policy_lists, history, withdrawn, applies_to: [cli, factory, device, intake], expect: accepted|refused, finding: {kind, requirement, path}}`. `applies_to` says which verifiers run the case: the downgrade cases and the new-bundle-from-a-withdrawn-base case apply to the CLI and the factory only, because only they hold a registry (PUB-131, PUB-133). Rules are the steps of §6 and the items of §7. The file lists, at least, the accepted and the refused case of every rule named in the Verification Plan.

#### 255. `crates/contexts/instrument/tests/overlay/bases/locked-groups/instrument.yaml` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: bases
*   **Proposed Changes**: A `locked` yes/no survey in groups with an introduction (original text, never from a real questionnaire), with a Spanish catalogue next to it.

#### 256. `crates/contexts/instrument/tests/overlay/bases/extend-end/instrument.yaml` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: bases
*   **Proposed Changes**: The same content with `modification: extend` and `end` only.

#### 257. `crates/contexts/instrument/tests/overlay/bases/extend-named/instrument.yaml` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: bases
*   **Proposed Changes**: `extend` with a named point `after-section-b` and its marker.

#### 258. `crates/contexts/instrument/tests/overlay/bases/modify/instrument.yaml` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: bases
*   **Proposed Changes**: No policy (defaults to `modify`).

#### 259. `crates/contexts/instrument/tests/overlay/bases/lists/instrument.yaml` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: bases
*   **Proposed Changes**: `extend` with `overlay-publishers` and `translators` lists of test key ids.

#### 260. `crates/contexts/instrument/tests/overlay/bases/downgrade/instrument.yaml` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: bases
*   **Proposed Changes**: Versions `1.0.0` (`locked`), `1.1.0` (`modify`, no marker: refused), `1.2.0` (`modify` with `relaxes`: accepted) and `1.3.0` (a point removed: accepted) as four files.

#### 261. `crates/contexts/instrument/tests/overlay/overlays/accepted/` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: accepted overlays
*   **Proposed Changes**: One folder per accepted case, each with an `overlay.yaml` and, where needed, `i18n/`: `end-two-questions`, `named-point`, `modify-base-any-change`, `base-metadata-only`, `extra-language-undeclared-by-base`, `added-check-reads-base`, `added-element-gated-on-base-answer`, `language-only-listed-translator`, `language-only-base-publisher`, `listed-overlay-publisher`, `no-publisher-list`, `tightened-no-marker`, `relaxed-with-marker`, `existing-overlay-of-withdrawn-base`.

#### 262. `crates/contexts/instrument/tests/overlay/overlays/refused/` (Create)

*   **Phase**: 16
*   **Type / Scope**: Overlay fixtures: refused overlays
*   **Proposed Changes**: One folder per refused case: `changed-label`, `removed-item`, `reordered-items`, `changed-code-list`, `changed-rule`, `added-probe`, `added-broad-answer`, `added-verify`, `content-outside-slot`, `undeclared-point`, `extension-under-locked`, `added-check-skips-base`, `added-check-derives-base`, `added-path-shadows-base`, `forged-address`, `base-unverifiable`, `unlisted-overlay-publisher`, `unlisted-translator`, `translator-not-base-publisher`, `overlay-of-an-overlay`, `downgrade-without-marker`, `point-added-without-marker`, `withdrawn-base-new-bundle`.

#### 263. `crates/apps/e2e/tests/overlay_matrix.rs` (Create)

*   **Phase**: 16
*   **Type / Scope**: End-to-end test: all four verifiers on one vector file
*   **Proposed Changes**: Reads `vectors.json` and, for every case, builds the base and overlay publications with test keys and runs: (1) `survey check` as a library call; (2) the factory's `BundleBuilder::build`; (3) the device's `Runtime::import_bundle` with the memory adapters; (4) intake's gate over a record of the overlay. For an accepted case all four accept; for a refused case all four refuse with the same finding kind, requirement and path (the intake result is the held reason plus the finding text). The case ids are test names through a generated list so a missing case is a compile-time gap, not a skipped test. Covers INS-282 to INS-285, PUB-128 to PUB-134, DIS-086, DIS-087, INT-093.

#### 264. `crates/apps/cli/src/conformance_cmd/ins_overlay.rs` (Modify)

*   **Phase**: 16
*   **Type / Scope**: Instrument conformance checks
*   **Proposed Changes**: Run the `check` half of every case of `vectors.json` (suite `ins-overlay`), so the core is pinned even where the others are not built.

#### 265. `crates/apps/cli/src/conformance_cmd/publishing.rs` (Modify)

*   **Phase**: 16
*   **Type / Scope**: Publishing conformance checks
*   **Proposed Changes**: Run the `authorise` and `check_downgrade` half of every case (suite `publishing`).

#### 266. `crates/adapters/file/tests/intake_ports.rs` (Modify)

*   **Phase**: 16
*   **Type / Scope**: File adapter tests
*   **Proposed Changes**: Add `int_093_the_published_instruments_reader_returns_publications_by_address` for the base and overlay of one case.

#### 267. `docs/reference/conformance.md` (Modify)

*   **Phase**: 16
*   **Type / Scope**: Documentation
*   **Proposed Changes**: Regenerated suite and matrix tables.

**Phase 17: ADR 0043 and the documentation of Part B**

#### 268. `docs/explanation/adr/0043-survey-overlays-and-the-modification-policy.md` (Create)

*   **Phase**: 17
*   **Type / Scope**: ADR
*   **Proposed Changes**: Status Proposed, priority Must. Decides: the three policies and the signed base; the overlay document and why it is published resolved; the one check (`overlay::check`) and the one authorisation (`verify_overlay`) shared by four verifiers; the projection comparison and why it covers aids; signer allow-lists and the translation rule (D17, D19); policy downgrade and `relaxes`; one level only (D15); extension points (D14); lineage at intake (D16); the licence as lint only (D18); the threats table of the brief (forged address, downgrade, mixed data, withdrawal, verifier disagreement). Records the counter-arguments as risks, the salted base address and the translation-key consequence. Depends on ADR 0030, 0041 and 0042.

#### 269. `docs/explanation/adr/README.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: ADR index
*   **Proposed Changes**: Add the row for 0043.

#### 270. `docs/explanation/adr/0030-public-transparency-log.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: ADR
*   **Proposed Changes**: Add "Used by ADR 0043" in the consequences: the downgrade check reads the registry, because the log holds no names.

#### 271. `docs/explanation/adr/0041-survey-source-tree-and-authoring-toolchain.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: ADR
*   **Proposed Changes**: Add the overlay folder to the survey source tree, one sentence and a link.

#### 272. `docs/reference/glossary.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: Glossary
*   **Proposed Changes**: Add: base, overlay, modification policy, extension point, inherited and added content, translator, overlay publisher, relaxes.

#### 273. `docs/how-to/runbooks/publish-an-instrument.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: Runbook
*   **Proposed Changes**: Add publishing an overlay: publish the base first, keep its `.published` file, pass it as `--base`, and what each refusal means.

#### 274. `docs/how-to/runbooks/README.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: Runbook index
*   **Proposed Changes**: No new runbook; the line for `publish-an-instrument` mentions overlays.

#### 275. `docs/tutorials/write-and-publish-your-first-survey.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: Tutorial
*   **Proposed Changes**: A closing section, "Extend a standard survey": `new overlay`, `survey check --base`, publish. It uses the examples of Phase 18 only by name, so the tutorial's own commands do not depend on them.

#### 276. `docs/index.md` (Modify)

*   **Phase**: 17
*   **Type / Scope**: Documentation index
*   **Proposed Changes**: Link ADR 0043.

**Phase 18: Examples migration and the one re-baseline**

#### 277. `examples/surveys/school-meals-baseline/instrument.yaml` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example survey
*   **Proposed Changes**: Migrated to the new keys: `short-label` on the questions that show in the review; real read-aloud labels for `weight`, `height` and the other headings ("How much does the pupil weigh?"); `probes` on two questions (for example `meal_which` and `shop_buys`), each with two or three follow-ups; a hierarchical food-group list (`parent`) with `broad-answer: allowed` on one new `choice` question and a follow-up shown when `under: [food_group, cereals]`; and a new `pupil_ref` text question with `verify: retype`. This is the one change that moves the example's address.

#### 278. `examples/surveys/school-meals-baseline/i18n/es.po` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example catalogue
*   **Proposed Changes**: Spanish text for every new or changed string, including each probe (`instrument/<path>.probes.<id>`), each short label and the new list. A missing probe translation is an error (INS-263).

#### 279. `examples/surveys/school-meals-baseline/layouts/compact.yaml` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example layout
*   **Proposed Changes**: Place `about.pupil_ref` and the food-group question; a question not placed is an error (INS-200).

#### 280. `examples/surveys/school-meals-baseline/layouts/expanded.yaml` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example layout
*   **Proposed Changes**: The same placement for the expanded window.

#### 281. `examples/surveys/household-water-access/instrument.yaml` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example survey
*   **Proposed Changes**: A `parent` grouping of the water sources (improved and unimproved headings) over the list that today's `concept` classification already suggests. It is a `both` survey, so it uses headings only: no `broad-answer`, no probes, no verification (D11).

#### 282. `examples/surveys/household-water-access/i18n/es.po` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example catalogue
*   **Proposed Changes**: Spanish labels for the two parent codes.

#### 283. `examples/surveys/diet-recall-standard/instrument.yaml` (Create)

*   **Phase**: 18
*   **Type / Scope**: Example survey: a standard
*   **Proposed Changes**: An original, project-written `locked` survey for the overlay examples: an introduction to read aloud and a yes/no question for each of about twenty generic food groups, in four groups, `administration: interviewer`, `modification: extend`, `extension-points: []` (only `end`), `copyright: {…, licence: Apache-2.0}`. Written for this project; it quotes no real questionnaire.

#### 284. `examples/surveys/diet-recall-standard/i18n/es.po` (Create)

*   **Phase**: 18
*   **Type / Scope**: Example catalogue
*   **Proposed Changes**: Complete Spanish catalogue.

#### 285. `examples/surveys/diet-recall-programme/overlay.yaml` (Create)

*   **Phase**: 18
*   **Type / Scope**: Example survey: an overlay
*   **Proposed Changes**: An overlay of `diet-recall-standard` that adds two questions at `end` (one number, one choice with an inline list). It omits `base.address` (see Decisions made while planning); `survey check --base` fills it.

#### 286. `examples/surveys/diet-recall-programme/i18n/es.po` (Create)

*   **Phase**: 18
*   **Type / Scope**: Example catalogue
*   **Proposed Changes**: Spanish text for the two added questions.

#### 287. `examples/README.md` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Documentation
*   **Proposed Changes**: Describe the two new example surveys and the migrated ones; say that the standard is original and that the overlay needs its base published first.

#### 288. `examples/scenarios/school-meals-baseline.yaml` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example scenario
*   **Proposed Changes**: Add `retype: {about.pupil_ref: "P-0042"}` to the capture steps that seal, a scripted mismatch for p-001 (`expect: mismatch`), and the food-group answer at the parent code with its follow-up.

#### 289. `examples/scenarios/stack-capture-school-meals-baseline.yaml` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Example scenario
*   **Proposed Changes**: The same `retype` step so the stack's capture still seals.

#### 290. `crates/apps/e2e/src/lib.rs` (Modify)

*   **Phase**: 18
*   **Type / Scope**: End-to-end helpers
*   **Proposed Changes**: `survey` (line 81) resolves an overlay folder against its sibling base source and the base's pinned-salt address (`pinned_salt`, line 94), so the overlay example loads like any survey. Add the two new names to the helpers that list surveys.

#### 291. `crates/apps/e2e/tests/migration_gate.rs` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Migration gate
*   **Proposed Changes**: `SURVEYS` (line 21) lists the four examples; the gate's `record` (line 41) handles an overlay through `survey`.

#### 292. `crates/apps/e2e/tests/golden/examples.json` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Golden record (re-baselined)
*   **Proposed Changes**: Regenerated with `FIELDSEAL_GOLDEN=write cargo test -p fieldseal-e2e --test migration_gate` in this commit only: new addresses, fingerprints and layout addresses for the two migrated surveys, and entries for the two new ones. The commit message lists every old and new address.

#### 293. `crates/apps/e2e/tests/golden/expanded/school-meals-baseline/instrument.json` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Golden record (re-baselined)
*   **Proposed Changes**: Regenerated expanded instrument.

#### 294. `crates/apps/e2e/tests/golden/expanded/school-meals-baseline/layout-compact.json` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Golden record (re-baselined)
*   **Proposed Changes**: Regenerated, with the bound instrument fingerprint.

#### 295. `crates/apps/e2e/tests/golden/expanded/school-meals-baseline/layout-expanded.json` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Golden record (re-baselined)
*   **Proposed Changes**: Regenerated.

#### 296. `crates/apps/e2e/tests/golden/expanded/household-water-access/instrument.json` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Golden record (re-baselined)
*   **Proposed Changes**: Regenerated.

#### 297. `crates/apps/e2e/tests/golden/expanded/household-water-access/layout-compact.json` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Golden record (re-baselined)
*   **Proposed Changes**: Regenerated.

#### 298. `crates/apps/e2e/tests/golden/expanded/diet-recall-standard/instrument.json` (Create)

*   **Phase**: 18
*   **Type / Scope**: Golden record
*   **Proposed Changes**: New.

#### 299. `crates/apps/e2e/tests/golden/expanded/diet-recall-programme/instrument.json` (Create)

*   **Phase**: 18
*   **Type / Scope**: Golden record
*   **Proposed Changes**: The resolved overlay (base content, slot, `spec.base`).

#### 300. `crates/apps/cli/tests/golden/school-meals-baseline.expanded.outline` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Golden record (re-baselined)
*   **Proposed Changes**: Regenerated outline of the rendered example (the new controls). The `.plan` goldens in `crates/contexts/instrument/tests/golden/` are expected to show no difference, because plan fields are written only when used; a difference there is a defect to explain, not a file to bless.

#### 301. `crates/apps/web/src/catalogue.rs` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Web app: survey list
*   **Proposed Changes**: A folder with `overlay.yaml` is listed as an entry with a note ("an overlay; exercised through publishing, the factory and the device") and no preview, because the stand-in has no published base to resolve it against. It is not an error and does not stop `parity.rs`.

#### 302. `tools/dev-publish.sh` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Dev tool
*   **Proposed Changes**: `survey_folder` (line 75) accepts a folder with `overlay.yaml`. `--all` (line 135) publishes every `instrument.yaml` folder first, then each overlay with `--base` set to the `.published` file of its base (found in `$PUB`), and passes `--base-source` so a translation can be checked. The salt file of the base is used for the base's address; the overlay's own salt is made like any other.

#### 303. `tools/dev-web.sh` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Dev tool
*   **Proposed Changes**: The post-start checks (lines 329 to 391) expect the Publishing page to list the new surveys; the survey-cohort map (line 221) is unchanged.

#### 304. `tools/browser-tests/device-flow.js` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: Already types the retype question twice (Phase 9); here it also answers the food-group question and the new follow-up.

#### 305. `tools/browser-tests/demo-e2e.py` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Browser tests
*   **Proposed Changes**: The seal step expects the new question count.

#### 306. `crates/adapters/web/tests/device_flow.rs` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Web adapter tests
*   **Proposed Changes**: The scripted capture of the example answers the new questions and retypes `pupil_ref`.

#### 307. `crates/apps/web/tests/parity.rs` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Web tests
*   **Proposed Changes**: The parity test covers the migrated examples' probes, hierarchy and verify markup in all layouts and languages.

#### 308. `docs/tutorials/hands-on.md` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Tutorial
*   **Proposed Changes**: Step 2 (publish) names the four example surveys and the order; step 9 (capture) mentions typing the pupil reference twice.

#### 309. `docs/reference/spec/instrument.md` (Modify)

*   **Phase**: 18
*   **Type / Scope**: Specification
*   **Proposed Changes**: The section 6.1 example and any text that quotes the example's labels, if present, match the migrated example. Re-run `tools/test-inventory.py` after this phase.

**Phase 19: Rollout runbook**

#### 310. `docs/how-to/amend-schema-1.0.md` (Create)

*   **Phase**: 19
*   **Type / Scope**: How-to (runbook)
*   **Proposed Changes**: What one must still do after the in-place amendment, in this order: rebuild the CLI, the factory and the web device from the same commit (builds from different commits disagree on fingerprints); `just purge` any local stack, because stored publications, bundles and the log carry the old addresses; republish the examples with `just publish` or `tools/dev-publish.sh --all` (bases before overlays); check with `just migration-gate` and `just acceptance`. Says what a mismatch looks like (a fingerprint the intake does not know) and that the release has no data to migrate (D1). Revisit at M5.

#### 311. `docs/how-to/run-the-local-stack.md` (Modify)

*   **Phase**: 19
*   **Type / Scope**: How-to
*   **Proposed Changes**: A pointer to the runbook after the `just purge` section.

#### 312. `docs/how-to/build-and-check.md` (Modify)

*   **Phase**: 19
*   **Type / Scope**: How-to
*   **Proposed Changes**: Add the new suites (`ins-labels`, `ins-probes`, `ins-hierarchy`, `ins-verify`, `ins-overlay`, `ins-ui-constraints`, `col-verify`) and the overlay matrix test to the list of what `just test` runs.

#### 313. `docs/index.md` (Modify)

*   **Phase**: 19
*   **Type / Scope**: Documentation index
*   **Proposed Changes**: Link the runbook.

### Verification Plan

Each phase's gate is a subset of this plan. Nothing here needs CI: the repository runs Actions only on `v*` tags, so every command is run locally (`nix develop path:. -c …`).

**1. The workspace gate, every phase.** `nix develop path:. -c just test` runs, in order:

*   `python3 tools/test-inventory.py --check`: every test names a requirement a spec defines, and `docs/reference/test-inventory.md` is current. A requirement must be in its spec before its tests count, which is why each phase edits both.
*   `python3 tools/check-example-paths.py`.
*   `tools/test-budget.sh`: `cargo nextest run --workspace` and the doc tests inside 20 seconds. The overlay matrix, the 2,000-code check and the corpus run inside this budget (small in-memory documents, no network). If a phase pushes the suite over, the fix is a faster test, not a longer budget.
*   `cargo clippy --workspace --all-targets --locked -- -D warnings`.
*   `python3 tools/check-architecture.py` against `architecture.toml`: no new edge is needed (publishing already depends on instrument; distribution, collection and intake already depend on both), and no crate is added to `inner_external_allow`.
*   `python3 tools/check-example-licences.py` and its `--self-test`: the new example surveys declare Apache-2.0 and a named holder.

**2. Conformance.** `fieldseal conformance run` (all suites), and by name after the phase that adds them: `ins-labels`, `ins-probes`, `ins-hierarchy`, `ins-verify`, `ins-overlay`, `ins-ui-constraints`, `col-verify`, plus the existing `ins-rules`, `ins-eval`, `strict-schema`, `publishing`, `distribution`, `col-lifecycle`. `fieldseal conformance matrix` regenerates `docs/reference/conformance.md`; a test in `crates/apps/cli/tests/conformance.rs` fails when it is stale.

**3. The browser constraint suites.**
*   `FIELDSEAL_BROWSER_TESTS=1 cargo test -p fieldseal-web --test browser_constraints` plays `tests/constraints/scenarios.json` (constraints and aids) in headless Chromium, for first collection and resurvey.
*   `just a11y` (instruments) and `just a11y http://127.0.0.1:18110` (with the web app): axe-core for WCAG 2.0, 2.1 and 2.2 A and AA, plus 2.4.11, 2.5.8, 1.4.10 and 1.4.12, over the corpus page with each control open.
*   The same scenarios run in the Device page through `device-flow.js`, so the page and the device that seals records agree.

**4. The dev loop.** `tools/dev-web.sh --check --browser` (ports, edit-and-reload, cookie scoping, the demo's eight steps). Its capture step types `pupil_ref` twice and seals, and its Publishing page lists the two new surveys after `dev-publish.sh --all` published the standard before the overlay.

**5. The stack.** `just purge`, then `just acceptance`: every walkthrough step, headless, against a fresh stack. It runs the school-meals scenario with `retype`, the factory's bundle build, the device's import and the intake of the sealed records. It does not build a bundle for an overlay (see the risks below); the overlay path is covered by item 7.

**6. The golden and migration-gate re-baseline.**
*   In Phases 1 to 17, `just migration-gate` and `additive_schema` pass with the golden set unchanged. A change that moves a byte there is a defect in the phase.
*   In Phase 18 the golden set is regenerated once, in one commit, with `FIELDSEAL_GOLDEN=write cargo test -p fieldseal-e2e --test migration_gate`. The reviewer reads the diff of `examples.json`: only the two migrated surveys change, the two new ones appear, salts are unchanged, and the commit message lists every old and new address. `additive_schema` still passes on the pre-amendment fixture, which shows that an instrument that uses none of the new keys keeps its bytes.
*   Revert rehearsal: revert the Phase 18 commit on a scratch copy and run `just test` and `just migration-gate`; both pass with the earlier examples and goldens.

**7. The overlay fixture matrix.** `cargo nextest run -p fieldseal-e2e --test overlay_matrix` runs every case of `crates/contexts/instrument/tests/overlay/vectors.json` through all four verifiers (`survey check`, the factory's bundle build, the device's bundle import, intake's gate), and asserts that they agree on the result and on the finding kind, requirement and path. A coverage test in the same file lists the rules below and fails when one has no accepted or no refused case. `ins-overlay` and `publishing` run the core and authorisation halves of the same file without the app crates.

| Rule | Accepted | Refused |
|---|---|---|
| §6.1 a `modify` base enforces nothing | `modify-base-any-change` | `changed-label` (same change, locked base) |
| §6.2 placement in declared slots | `end-two-questions`, `named-point` | `content-outside-slot`, `undeclared-point`, `extension-under-locked` |
| §6.3 and §6.4 projection equals the base | `base-metadata-only`, `extra-language-undeclared-by-base` | `changed-label`, `removed-item`, `reordered-items`, `changed-code-list`, `changed-rule` |
| Aids are locked (§6.4) | `end-two-questions` (aids on added questions) | `added-probe`, `added-broad-answer`, `added-verify` |
| §6.5 added rules read, never change, base answers | `added-check-reads-base`, `added-element-gated-on-base-answer` | `added-check-skips-base`, `added-check-derives-base` |
| §6.6 added paths live under the slot | `end-two-questions` | `added-path-shadows-base` |
| §6.7 a language-only overlay is a translation | `language-only-listed-translator`, `language-only-base-publisher` | `unlisted-translator`, `translator-not-base-publisher` |
| One level only | `end-two-questions` | `overlay-of-an-overlay` |
| §7 base in the log, address equal | `end-two-questions` | `forged-address`, `base-unverifiable` |
| §7 `overlayPublishers` | `listed-overlay-publisher`, `no-publisher-list` | `unlisted-overlay-publisher` |
| §7 policy downgrade | `tightened-no-marker`, `relaxed-with-marker` | `downgrade-without-marker`, `point-added-without-marker` |
| §6 withdrawn base | `existing-overlay-of-withdrawn-base` | `withdrawn-base-new-bundle` |

**8. Manual checks that no test replaces.**
*   The answer to D7 from the collectors is recorded in ADR 0042 before it is Accepted.
*   A person reads the probe chips, the broad-answer action and the retype step with a screen reader once (the automated checks do not judge reading order or wording).
*   Every new example text is read once for originality: it must not quote or paraphrase any real questionnaire.

### Risks the Technical Plan does not cover

*   **Intake cannot re-check the verify gate.** §5 says intake re-checks it on replay, but nothing about verification is stored (D4, WIRE-052), so a record holds nothing to replay. The guarantee is the seal gate plus the device refusing, at import, an instrument whose constraint kinds it does not enforce (COL-113). INT-012 replay is unchanged for verify items. The text of INS-275 states this honestly instead of promising a check that cannot exist.
*   **The base address is a salted fingerprint.** An instrument's address is `SHA-256` over a random per-publication salt and the bytes (PUB-090), so an overlay in a repository cannot name a stable address, and a translation cannot be keyed from the canonical form, which has no `msgctxt`. Phase 12 resolves both with a smaller step than the plan assumed (an omitted `address` is filled at check time, and a translation overlay needs `--base-source`), and the ADR records the cost.
*   **The `.probes` fold rule in §3 and the `.unit` rule differ.** §3 says `.probes` follows the `.unit` fold and then describes keeping the set when the value is set, but `.unit` is replaced when a value is set (`landing.rs:100`). Phase 5 keeps both behaviours, one rule per annotation kind.
*   **A wire change.** `BundleContent.bases` is a new optional key of the bundle plaintext, so WIRE-094 and its CDDL change. It is additive and left out when empty, so existing bundles and vectors are unchanged.
*   **Downgrade is not checkable everywhere.** It needs the registry's earlier versions, so devices and intake rely on the factory having refused. A stolen factory key plus a base-publisher threshold is outside what this can detect.
*   **Nobody called `CheckCompatibility` at run time before.** Phase 3 is its first use by a runtime. A device built before it simply does not check; builds from one commit are the rollout rule anyway.
*   **Verify items touch every flow that seals school-meals.** The scripted scenarios, `device-flow.js`, `demo-e2e.py`, `device_flow.rs` and the stack capture all need a `retype` step (Phase 18). A missed one fails at its seal, which is loud, but the list is long.
*   **No stack-level overlay run.** `just acceptance` builds no bundle for an overlay. The in-process matrix covers the verifiers and `bundle-failed`, but not the stack's registry, the factory's HTTP routes or the device's wasm build with a real overlay. Adding an assigned overlay to `tools/stack-demo.sh` is a follow-up.
*   **Probe use is information about a person.** Self-reported process data about collectors needs a privacy review before anyone builds reports from it (Security, above).

### Decisions made while planning

Each is the smallest choice consistent with the Technical Plan where the code did not settle the point.

1.  **`.unit` stays a non-node item.** `QuestionOrigin::Annotation` is added only for nodes (`.probes`). `.unit` is still recognised through the `Annotation` module, with a per-kind fold rule (`Replace` for the unit, `Keep` for probes), because replacing all `.unit` handling with a node would change landing, export and the data contract for no gain.
2.  **A missing label is an error for interviewer surveys only, and never for `roster` items.** The brief says "no filled-in labels for interviewer questions"; self-administered surveys keep the id fallback.
3.  **The heading-like label rule is "at most three words and no question mark, comma or full stop"**, advisory, once per declared question.
4.  **`ControlCatalogue::constraint_kinds` has no default, and the collection `Platform` gains a `catalogue`.** A default would claim enforcement nobody tested. The registration profile (WIRE-130) is not changed; the device refuses at import.
5.  **The core owns the verification comparison** (`Capture::set_retyped`, `confirm_read_back`). The block at seal reuses the hard list (`<path> (INS-275)`), as the plan says ("a value problem"), instead of adding a `SealBlock` variant. A pause leaves unverified values out of the sealed content, so the first entry is never written and a pause cannot deadlock.
6.  **Added questions use inline code lists.** The projection of §6 forbids any new top-level code list, so overlay `lists:` expand to `Options::Inline`.
7.  **An extension point is an element marker `{kind: extension-point, name}`**, added paths are prefixed `extensions.<point>`, and `end` is handled by the compiler after the last top-level element. The names `extensions`, `base`, `probes` and `probe` are reserved (INS-276).
8.  **`base.address` may be omitted in `overlay.yaml`** and is filled from the base's publication at check and publish time. The resolved, published instrument always carries it. A translation overlay passes `--base-source` for the keys.
9.  **`verify_overlay` in Publishing composes the two functions of §6 and §7**, and `check_downgrade` is separate from `authorise`. §7 lists the downgrade under `authorise`, but it needs history that only some verifiers have, so it is a second function run where a registry exists. Its history is read from the registry, not the log (the log has no names, PUB-104).
10.  **`BundleContent.bases` is one optional list**, and the opened bundle carries `bases` next to its single `instrument` (a runtime holds one instrument per bundle).
11.  **`InstrumentSource::publication(address)`** is the one new call on the intake port, so intake runs `verify_overlay` itself and the adapters stay free of overlay logic.
12.  **The export version is 1.1.0 for both Phase 8 and Phase 14.** Both add columns before any release; a second bump would have no reader to protect.
13.  **The dialect reference is generated** by `schema export --markdown` and checked by a test; ADR 0040's key list becomes historical.
14.  **A probe translation gap is an error even without `--strict`**, as D13 requires, where other missing translations stay warnings (INS-260).
15.  **The web stand-in lists an overlay folder without a preview.** It has no published base to resolve against; overlays are exercised through publish, the factory, the device and intake.
16.  **The corpus has two kinds of scenario**, `constraint` (INS-252) and `aid` (probes, the broad-answer action). Aids are not constraints, but the same harnesses drive them, so one file serves the three UIs.
17.  **Factual corrections in earlier sections** (proved from the code and specs): INT-013 is the duplicate rule, so the intake reason is INT-093; the export has no `instruments.csv`, so lineage goes in the manifest, the codebook and the contract; the downgrade reads the registry, since the log holds no names.

*Drafted with EGM*
