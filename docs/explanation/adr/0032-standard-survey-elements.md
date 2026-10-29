# ADR 0032: Standard survey elements are first-class in the instrument schema

**Status:** Accepted (2026-10-27, architecture review #67) · **Priority:** Must · **Date:** 2026-10-27

**In one line:** The instrument schema gains the elements that established survey standards share (metadata, nested groups, repeats, reusable code lists, nonresponse codes, text roles, units, concepts, media), so a real instrument is written once, compactly, without workarounds.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The first real instrument, a food-frequency and diet-quality questionnaire, was checked against the Instrument spec as drafted. It has a demographics section and a grid of about 95 foods in 13 categories. Each food has a frequency (on one of two 9-step scales), an amount (in `oz`, `each` or 250 ml portions) and a "had it yesterday" answer. The spec could express each answer, but not the instrument as a whole:

| The questionnaire needs | Draft spec | Gap |
|---|---|---|
| The same 3 answers for each of 95 foods | Flat items only | No repeat or template; about 380 hand-written items and 95 copies of each rule |
| A food row as one unit, with a shared label and description ("White, wholewheat, rolls") | Items have one control each; no nesting | No nested groups; no description text |
| Two frequency scales, each reused by about 50 items | Options are inline | No named, reusable code lists |
| Frequencies analysed as times per day | Codes only | No numeric meaning per code |
| A portion of 0.5 cup; money in steps of 5 | `stepper` has no step size | No `step`; no currency |
| Weight entered in lbs or kg | One unit per item | No alternative entry units |
| "Other ______" rows; "What do you buy? 1–4" | `coded-list-with-other` is single-choice | No "other, specify" for multi-choice or for a repeat row |
| Instructions, the reference period ("in the last week"), "End of survey" | Section titles only | No display items or group descriptions |
| A child who doesn't know an amount | Unset or a value | No "don't know" or "refused" distinct from not asked |
| Collector instructions ("weigh twice") vs question text | One `hint` field, which is the data-contract hint | No text roles; a confusing name |
| The source instrument's copyright, and that it derives from a published instrument | Name and version only | No descriptive metadata, licence or derivation |
| Food groups mapped to a standard classification for indicators | None | No concept codes |
| Food pictures and icons in the wireframe | None | No media |
| Scale and stadiometer calibration, once per session | Items are per subject | No session-scoped items (Could) |

The established standards share most of these elements:
- **HL7 FHIR Questionnaire:** nested `group` and `display` items, `enableWhen` with `disabledDisplay`, `required`, `repeats`, `readOnly`, `answerOption`/`answerValueSet`, item `code`, `prefix`, and `copyright` and `derivedFrom` metadata.
- **XLSForm/ODK:** `relevant`, `constraint` with message, `required` with message, `calculation`, `choice_filter`, `appearance`, `hint` and `guidance_hint`, `begin group`/`begin repeat`, `select_one … or_other`, translations, media.
- **CDISC ODM:** `ItemGroupDef`, `ItemDef`, `CodeList`, `MeasurementUnit`, `RangeCheck` (soft and hard), `ConditionDef`, `MethodDef`.
- **Survey archives (DDI practice):** explicit nonresponse categories ("don't know", "refused", "not applicable"), always kept separate from valid values.

## Decision

The instrument schema MUST provide each element below as a first-class construct, specified in the [Instrument spec](../../reference/spec/instrument.md) §5.11–5.20.

| Element | Priority | Decision |
|---|---|---|
| Descriptive metadata | Must | `title`, `description`, `purpose`, `publisher`, `copyright`, `derivedFrom` and `administration` (`interviewer`, `self` or `both`) |
| Nested groups | Must | A tree of `group`, `question` and `display` elements; groups carry a label, description and reference period, and prefix their children's paths |
| Display elements | Must | Instructions and notes that record nothing |
| Static repeats | Must | A group repeated over the codes of a code list (one row per food), with rules written once using relative paths |
| Reusable code lists | Must | Named lists with stable codes, an `ordered` flag, an optional numeric `value` per code, `exclusive` codes, and "other, specify" |
| Nonresponse | Must | `dont-know` and `refused` are opt-in per item and recorded as such; `not-applicable` is derived from skip logic; unset means not asked. Never encoded as numbers. |
| Text roles | Must | `label`, `shortLabel`, `prefix`, `help` (for the subject and collector) and `guidance` (collector only); the data-contract `hint` is renamed `data` |
| Units and money | Must | UCUM canonical units, alternative entry units with exact conversion, stepper `step`, and ISO 4217 currency |
| Concept codes | Should | Items and codes MAY map to external terminologies (for example LOINC, a food-group classification) |
| Media | Should | Images and icons embedded by content address, with required alternative text |
| Session-scoped items | Could | Items answered once per session (for example equipment checks) and referenced by subject records |
| Option-order randomisation | Could | Seeded per record and recorded, for nominal lists only |
| Dynamic repeats (household members) | Could | Deferred to schema minor 1.1 |
| Defaults and pre-selection | Won't | Contradicts INS-021: nothing is written that the collector did not set |
| Per-item timing paradata | Won't | The record's ticks are enough; finer paradata adds re-identification risk on shared devices |

- These elements are **content**: they change what is recorded and how it is analysed, so they are covered by the instrument's fingerprint ([ADR 0027](./0027-salted-instrument-fingerprints.md)). How they are arranged on screen is not content ([ADR 0033](./0033-presentation-layouts.md)).
- Rules MUST stay within the bounded language of [ADR 0010](./0010-declarative-instruments.md). Relative paths inside repeats are expanded when the instrument is compiled, so the evaluator gains no loops.

## Consequences

- The questionnaire becomes about 13 repeat groups over 13 code lists, 2 shared scales and 1 rule per row type, instead of about 380 items and 95 copies of each rule.
- Intake's generated data contract gains a nonresponse column and numeric code values. "Don't know" can be analysed separately from "not asked".
- Instruments derived from published instruments, such as the DQQ, carry their attribution and licence with them.
- The schema stays at `1.0`: none of this has been released. Dynamic repeats and session-scoped items will arrive as minor versions.

## Specs

[instrument](../../reference/spec/instrument.md) §5.11–5.20, [wire formats](../../reference/spec/wire-formats.md) WIRE-051, WIRE-052, [intake](../../reference/spec/intake.md)
