# Instrument

**Prefix:** `INS` · **Kind:** `Instrument` · **apiVersion:** `fieldseal.dev/v1alpha1` · **Status:** Draft

## 1. Scope

This spec covers the Instrument bounded context: the model of what a deployment collects, and how the runtime and intake interpret it.

**Owns:**
- descriptive metadata ([ADR 0032](../../explanation/adr/0032-standard-survey-elements.md));
- the element tree: groups, questions, display elements and repeats;
- items and item paths;
- code lists, nonresponse codes, text roles, units, concept codes and media;
- the control catalogue;
- atomic groups;
- the rule language (validation and skip predicates; the tool derives nothing, §5.22);
- field checks;
- consent requirements;
- data-contract hints;
- localisation;
- the instrument schema version and runtime compatibility;
- fingerprints ([ADR 0027](../../explanation/adr/0027-salted-instrument-fingerprints.md));
- layouts and the render plan compiled from instrument and layout ([ADR 0033](../../explanation/adr/0033-presentation-layouts.md));
- the rule that the tool derives nothing (§5.22), the standard unit catalogue (§5.23), extensions (§5.24) and entry-time constraint enforcement (§5.25).

**Does not own:**
- publishing and signing an instrument: [Publishing](./publishing.md);
- how an instrument reaches a device: [Distribution](./distribution.md);
- how a collector moves through it, and how a platform draws a render plan: [Collection](./collection.md), [Platform profiles](./platform-profiles.md);
- how intake replays its rules: [Intake](./intake.md);
- byte encodings: WIRE §canonical-encoding and WIRE §content-address.

## 2. Domain model

| Element | Type | Meaning |
|---|---|---|
| `Instrument` | Aggregate root | A complete, immutable definition of what is collected, identified by its salted fingerprint (INS-100). |
| `InstrumentId` | Value object | A stable, human-chosen name (for example `health-check`), plus `version` (semantic version of the instrument's own content). Labels only (INS-101). |
| `InstrumentMetadata` | Value object | Title, description, purpose, publisher, copyright, derivation and administration mode (§5.11). |
| `ContentAddress` | Value object | `sha256:` of the instrument's canonical bytes (WIRE §content-address). |
| `SchemaRange` | Value object | The instrument-schema version range the instrument needs (for example `^1.0`). |
| `Element` | Entity | A node of the element tree: a `Group`, a `Question` or a `Display` (§5.12). |
| `Group` | Entity | A labelled set of elements that prefixes its children's paths; MAY repeat over a code list (§5.13). Replaces *section*. |
| `Question` | Entity | One item that records a value, addressed by an `ItemPath`. Called an *item* elsewhere in the specs. |
| `Display` | Entity | Text or media that records nothing: instructions, notes, an end message. |
| `ItemPath` | Value object | Dot-separated lowercase identifiers, unique in the instrument (for example `body.weight`, `diet.bread.freq`). |
| `CodeList` | Entity | A named, reusable list of codes with localised labels, an `ordered` flag, optional numeric values, exclusive codes and an "other" code (§5.14). |
| `Nonresponse` | Value object | `dont-know` or `refused`, entered by the collector; or `not-applicable`, derived from skip logic (§5.15). |
| `Control` | Value object | A catalogue control type with its configuration. |
| `Unit` | Value object | A UCUM unit or ISO 4217 currency, with alternative entry units (§5.17). |
| `Concept` | Value object | A code in an external terminology `{system, code}` (§5.18). |
| `Media` | Value object | An embedded image by content address, with alternative text (§5.19). |
| `AtomicGroup` | Entity | A set of item paths that are always written together. |
| `Rule` | Entity | A validation or skip rule in the rule language. It never produces a value (INS-227). |
| `StandardCatalogue` | Value object | The versioned, content-addressed set of units shipped with the format core: UCUM measures, household measures and ISO 4217 currencies (§5.23). |
| `Extension` | Aggregate root, artefact | A signed, published, additive set of custom units, code lists and concept schemes (§5.24). |
| `FieldCheck` | Entity | A rule over many records in the local record. |
| `ConsentRequirement` | Value object | Whether consent is needed, which bases are allowed, whether evidence is allowed or required. |
| `DataSpec` | Value object | The type, unit, code list, concept and sensitivity of an item, for intake's generated data contract (§5.8). Formerly *data-contract hint*. |
| `LocalisedText` | Value object | A map of language tag (BCP 47) to text. |
| `Layout` | Aggregate root | A separate artefact arranging one instrument's questions into containers, bound to that instrument's fingerprint (§5.20). |
| `RenderPlan` | Value object | The platform-neutral tree compiled from an instrument and a layout: containers, controls, and visibility bound to rules. |

**Domain events:**
- `InstrumentValidated`;
- `LayoutValidated`;
- `InstrumentRejected(reason)`;
- `RuleEvaluated(rule, verdict)`;
- `FieldCheckRaised(check, records)`.

**Invariants:**
- An instrument is immutable once content-addressed.
- Item paths are unique.
- Every rule and field check refers only to item paths in the same instrument.
- Every rule terminates (INS-044).
- A layout places every question of its instrument exactly once, in the instrument's order, and changes no content (INS-202, INS-203, INS-214).

## 3. Driving ports

| Port | Input | Output | Errors |
|---|---|---|---|
| `ValidateInstrument` | Authoring document, decoded from YAML or JSON by an adapter | `Instrument` with its fingerprint, or findings | `SchemaViolation`, `UnknownControl`, `UnknownItemPath`, `UnboundedRule`, `IncompatibleSchemaRange` |
| `LintInstrument` | `Instrument` | Advisory findings (unused items, untranslated text, missing hints) | — |
| `CheckCompatibility` | `Instrument`, runtime's supported schema version | `compatible` or `incompatible(reason)` | — |
| `EvaluateRules` | `Instrument`, a record's item values | Verdicts per rule: `pass`, `hard`, `soft`, plus skip states | `EvaluationLimitExceeded` |
| `EvaluateFieldChecks` | `Instrument`, a set of records | Raised field checks with the records involved | `EvaluationLimitExceeded` |
| `ValidateLayout` | `Layout`, the `Instrument` it is bound to | `Layout` with its content address, or findings | `FingerprintMismatch`, `UnplacedQuestion`, `DuplicatePlacement`, `OrderChanged`, `ContentOverride`, `UnsupportedPresentation` |
| `LintLayout` | `Layout`, `Instrument`, lint thresholds | Advisory choice-load findings (INS-210–INS-213) | — |
| `CompileRenderPlan` | `Instrument`, `Layout` (with its content address) or none, locale, window class | A `RenderPlan`; with no layout, the default layout (INS-206) | `LayoutMismatch` (the layout was validated against another instrument) |
| `ResolveVisibility` | `RenderPlan`, its `Instrument`, current values and roster | Which nodes are visible, protected or hidden now | `EvaluationLimitExceeded` |

## 4. Driven ports

Canonical encoding and hashing are pure functions of the format core ([Wire formats](./wire-formats.md)), not ports, so they have no adapters.

| Port | Contract |
|---|---|
| `ControlCatalogue` | Reports the control types, presentations, container types and renderable languages (scripts, fonts, directions) a runtime supports, and the schema version it implements. Each platform's UI adapter provides one; it MUST NOT advertise a control, presentation or container it cannot render under the interaction rules of §5.3. |

## 5. Requirements

### 5.1 Document and identity

- **INS-001** An instrument MUST be a resource with `apiVersion: fieldseal.dev/v1alpha1`, `kind: Instrument`, `metadata.name`, `metadata.version` (semantic version) and `spec.schema` (a schema version range).
- **INS-002** The canonical bytes of an instrument MUST be produced by WIRE §canonical-encoding from the authoring form. Comments, key order and whitespace in the authoring form MUST NOT affect them.
- **INS-003** *Withdrawn ([ADR 0027](../../explanation/adr/0027-salted-instrument-fingerprints.md)): identity is the salted fingerprint, INS-100.*
- **INS-004** Every record about a subject MUST reference the fingerprint of the instrument it answers (WIRE §record-payload, WIRE-186).
- **INS-005** An instrument MUST NOT be used by a factory or runtime unless it has been published ([Publishing](./publishing.md)).
- **INS-006** Validation MUST reject unknown fields at every level.
- **INS-007** Every reader of an instrument, layout, localisation file or recorded value MUST be strict. It MUST reject unknown fields, enforce exact types (no coercion: the text `"4"` is not the integer 4, and a decimal is not an integer), match enums exactly, require every required field, and enforce every constraint the document declares (ranges, lengths, cardinality, `max` selections, code-list membership, patterns, references). A lax reader is a defect, not a convenience.

### 5.2 Items and paths

- **INS-010** *Withdrawn ([ADR 0032](../../explanation/adr/0032-standard-survey-elements.md)): sections are replaced by the element tree, INS-120.*
- **INS-011** Each question MUST have a unique `path`, a localised `label`, a `control`, and a `data` specification (§5.8). *(Amended 2026-10-27: `hint` renamed `data`.)*
- **INS-012** An item path MUST match `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$` and MUST NOT exceed 128 characters.
- **INS-013** An item MAY reference a roster field as a read-only value (for example a subject's age) through `from: roster.<field>`. Such an item MUST NOT be editable, and it MUST NOT be written to records unless `record: true` is set.
- **INS-013a** An item with `from: roster.<field>` MUST NOT declare a `control`, MUST declare `data`, and is rendered read-only. A question MAY opt out of the instrument's default nonresponse codes with `nonresponse: []`.
- **INS-014** An instrument MAY mark an item `optional: true`. Optional items are excluded from the unanswered count ([Collection](./collection.md)).

### 5.3 Control catalogue v1

The runtime MUST render each control under these interaction rules.

- **INS-020** Every control MUST have a visible **unselected** state. A control's initial state in first collection MUST be unselected.
- **INS-021** A value MUST be written to a record only when the collector set it. An unset control MUST be absent from the record: never `null`, zero, empty or a default.
- **INS-022** Placeholder or starting positions shown by a control (for example a stepper's first press value) MUST NOT be written unless the collector set them.
- **INS-023** In first collection, re-selecting the selected option of a single-choice control MUST do nothing. In a resurvey (a correction of an earlier record, see [Collection](./collection.md)), re-selecting the selected option MUST clear it.
- **INS-024** Irreversible actions (seal, record consent, clear, end tenancy) MUST use hold-to-confirm. Controls in this catalogue MUST NOT trigger irreversible actions.

| Control | Value type | Options | Notes |
|---|---|---|---|
| `choice` | One code | `options: [{code, label}]` or `codes: <code list>` | Single choice |
| `multi-choice` | Set of codes, plus `other` text | `options` or `codes`, `max` | Written as a whole set (atomic); honours `exclusive` and `other` codes (INS-133, INS-134) |
| `scale` | Ordinal 0..n | `steps: [{code, label}]` or `codes: <ordered code list>`, `presentation: slider \| segments` | Covers frequency scales; step 0 MAY be a "never"-type step but is not preselected |
| `stepper` | Decimal on a grid of `step` | `min`, `max`, `start`, `step` (default 1), `unit` | First press sets `start`; below `min` clamps in first collection and clears in a resurvey |
| `number` | Decimal | `min`, `max`, `decimals`, `unit`, `entryUnits` | Typed entry |
| `money` | Decimal | `min`, `max`, `currency`, `step` | Amount in the currency's major units (for example `20.50`), with at most its minor-unit digits (INS-162); presentations `stepper` or `entry` |
| `measurement-pair` | Two decimals | `min`, `max`, `decimals`, `unit`, `entryUnits`, `tolerance` | Two independent readings; atomic |
| `text` | String | `maxLength`, `multiline` | Free text |
| `coded-list-with-other` | One code, or `other` + text | `options`, `otherLabel`, `maxLength` | Code and text written together (atomic). With a code list that declares `other` (INS-134), `choice` behaves the same |
| `yes-no` | Boolean | `presentation: switch \| buttons` | Neither side lit until set |
| `date` | Calendar date | `min`, `max` | Collector-declared; not a trusted time |
| `photo-evidence` | Evidence reference | `maxDimension` | Only where the instrument's consent requirement allows evidence; capture rules in [Collection](./collection.md) |
| `consent-attestation` | Consent record | `bases`, `statement` | Used only by the consent step (§5.7) |

- **INS-025** A runtime MUST reject an instrument that uses a control type or option it does not support, where an option includes a fixed `presentation` (for example `scale` as `segments`). `CheckCompatibility` MUST report each control type and each fixed presentation the instrument uses that the runtime's `ControlCatalogue` does not list, and the instrument is not compatible while either list is non-empty.
- **INS-026** `measurement-pair` MUST treat the item as incomplete until both readings are set, and MUST raise a hard verdict when the readings differ by more than `tolerance`.
- **INS-027** Numeric controls MUST NOT accept a value outside `min`..`max`; such a value cannot be entered.

### 5.4 Atomic groups

- **INS-030** `measurement-pair`, `multi-choice` and `coded-list-with-other` items are atomic: all their parts MUST be written together or not at all.
- **INS-031** An instrument MAY declare further atomic groups (`atomicGroups: [{id, paths}]`) *(Amended 2026-10-27: was `groups`.)*. If any path in a group is written, every set path in the group MUST be written in the same record.

### 5.5 Rule language

Rules are declared in `spec.rules`, or in a group's `rules`, which scopes them to that group and, in a repeat, to each instance (INS-047). Each rule has an `id`, a `kind`, a `when` expression, and kind-specific fields.

| Kind | Effect when `when` is true |
|---|---|
| `hard` | Blocks sealing until resolved. Has a localised `message`. |
| `soft` | Shows **ask again** with the instrument's `reasons` (for example *unusual day*, *not sure*). The collector either changes an answer or picks a reason, stored as `override_reason`. |
| `skip` | Hides `targets` (item paths or group paths). Hidden items MUST be cleared from the pending record. |

Grammar (EBNF):

```
expr      = or ;
or        = and { "or" and } ;
and       = not { "and" not } ;
not       = [ "not" ] cmp ;
cmp       = sum [ ( "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" ) sum ] ;
sum       = term { ( "+" | "-" ) term } ;
term      = unary { ( "*" | "/" ) unary } ;
unary     = [ "-" ] atom ;
atom      = number | string | "true" | "false" | path | call | "(" expr ")" | list ;
path      = "$" itempath | "@" ident | "roster." ident ;
call      = fn "(" [ expr { "," expr } ] ")" ;
fn        = "is_set" | "is_nr" | "abs" | "min" | "max" | "count_set" | "round" | "lookup" | "value" ;
list      = "[" [ expr { "," expr } ] "]" ;
```

- **INS-040** Every rule expression MUST conform to the grammar above. There MUST be no user-defined functions, loops, recursion, variables, I/O or access to time.
- **INS-041** An expression referencing an unset item MUST evaluate that reference as *unset*. Any operator applied to *unset* MUST yield *unset*, except `is_set`, `is_nr` (INS-048) and `count_set`. A `when` that evaluates to *unset* MUST be treated as false.
- **INS-042** A rule MUST run on a device only when all item paths it references are set in the record being sealed or are read-only roster values. Rules that span records run at intake on the merged state ([Intake](./intake.md)).
- **INS-043** `lookup(table, key)` MUST read only from tables declared inside the instrument as `spec.tables: {<id>: {rows: [{key, value}]}}`, where every `key` in a table has the same type (integer, decimal or text) and no key repeats; `table` MUST be a string literal naming a declared table. A missing key MUST evaluate to *unset*.
- **INS-044** Evaluation MUST be bounded: an implementation MUST reject an instrument whose expression tree exceeds 256 nodes per rule or whose `lookup` tables exceed 10 000 rows in total, and MUST abort evaluation exceeding these limits with `EvaluationLimitExceeded`.
- **INS-045** *Withdrawn ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md)): the tool derives nothing. Replaced by INS-226 and INS-227.*
- **INS-046** Rule evaluation MUST be identical on every runtime and at intake: it is implemented once in the format core ([ADR 0005](../../explanation/adr/0005-format-core.md)).
- **INS-047** `@ident` MUST be allowed only in rules declared inside a repeat group, and MUST refer to the sibling question `ident` of the same repeat instance. Compilation MUST expand such a rule into one rule per instance before evaluation, so the evaluator sees only `$` paths; the expansion counts toward INS-044's limits.
- **INS-049** A rule `id` MUST be unique within the scope that declares it (the instrument, or one group). Its compiled identifier is the scope's path and the id joined by `.` (for example `diet.staples.bread.never-but-yesterday`), and compiled identifiers MUST be unique.
- **INS-048** `is_nr(path)` MUST be true when the item holds a nonresponse code (§5.15); every other operator MUST treat a nonresponse as *unset* (INS-041). `value(path)` MUST return the numeric `value` of the code the item holds (INS-132), or *unset*.

### 5.6 Field checks

Field checks run over the local record during review. They point out likely failures in the field; they never block sealing.

| Check type | Parameters | Raises when |
|---|---|---|
| `distribution` | `path`, `expected: {mean, sd}` or `{min, max}`, `minCount` | The cohort's values deviate from the expected range by more than the configured bound |
| `drift` | `path`, `window`, `threshold` | Consecutive values move steadily in one direction beyond `threshold`, in the item's unit (for example a scale going out of calibration). For a `measurement-pair` the series is the mean of each record's two readings. |
| `duplicates` | `paths`, `minMatch` | Two or more subjects' records match on at least `minMatch` of `paths` |
| `timing` | `minSeconds`, `maxSeconds` | A record's elapsed capture time (from its ticks) is outside the bounds |
| `completeness` | `group` or `paths`, `threshold` | The share of unanswered items exceeds `threshold` |
| `straightlining` | `group`, `threshold` | One option is chosen for more than `threshold` of a group's items |

- **INS-050** A field check MUST name a `type` from the table, its parameters and a localised `message`.
- **INS-051** Field checks MUST be evaluated only over the local record of the current tenancy and MUST NOT require any record to be decrypted from the journal.
- **INS-052** A raised field check MUST identify the records involved, so the collector can open each one.
- **INS-053** Field checks MUST NOT prevent sealing, export or clear.

### 5.7 Consent requirements

- **INS-060** An instrument MUST declare `spec.consent` with `required: true | false`.
- **INS-061** If consent is required, the instrument MUST list `bases` (codes and localised labels) a collector may attest, a versioned `statement`, and `evidence: none | optional | required`.
- **INS-062** If consent is not required, the runtime MUST NOT show the consent step, and records MUST reference `consent_basis: not-required`.

### 5.8 Data specification

- **INS-070** Each question's `data` MUST give `type` (`code`, `codes`, `integer`, `decimal`, `money`, `string`, `boolean`, `date`, `evidence`), and MAY give `unit` (UCUM), `codeList`, `concept` (§5.18), `sensitivity` (`normal`, `special-category`) and `description`. *(Amended 2026-10-27: was `hint`; adds `money` and `concept`.)*
- **INS-071** Intake MUST generate the instrument's data contract from these specifications ([Intake](./intake.md)). A question without a valid `data` MUST fail validation.
- **INS-072** The generated data contract MUST carry, for each question, its nonresponse state as a separate column from its value (INS-142), and, for coded items, each code's numeric `value` where the code list declares one (INS-132).

### 5.9 Internationalisation and localisation ([ADR 0034](../../explanation/adr/0034-internationalisation-and-localisation.md))

- **INS-080** All user-facing text MUST be `LocalisedText`. An instrument MUST declare `spec.languages` and a `defaultLanguage`; every text MUST have the default language.
- **INS-081** Records MUST store codes, never display text.
- **INS-082** Every `LocalisedText` in an instrument and its layouts MUST have a text for every language in `spec.languages`; a missing text MUST fail validation. Authors keep translations in `.po` catalogues. A language is either complete or not declared ([ADR 0034](../../explanation/adr/0034-internationalisation-and-localisation.md)).
- **INS-083** Each language other than `defaultLanguage` MUST declare `spec.translations.<tag>: {method: human | machine-assisted, reviewedBy: <count of reviewers>, notes?}`. Publishing review MUST cover every declared language ([Publishing](./publishing.md)). Authors SHOULD follow TRAPD (translation, review, adjudication, pretest, documentation).
- **INS-084** A text MAY be a Unicode MessageFormat 2 message that uses only variable references to roster fields (`$roster.<field>`) or item paths, and the `:number`, `:integer`, `:date` and plural or exact-match selectors. Every language of the same text MUST use the same set of variables. No other formatter or function MAY be used.
- **INS-085** Texts MUST be plain text: no markup, HTML or control characters other than line breaks. Bidirectional formatting characters MUST be limited to isolates (U+2066–U+2069).
- **INS-086** Media referenced by a text MAY vary by language (`media: {<tag>: <id>}`), for example images containing words; `alt` MUST still exist in every language (INS-181).
- **INS-087** Language selection MUST follow RFC 4647 lookup from the collector's chosen language to `defaultLanguage`. The render plan MUST carry, for the selected language, its tag and its text direction (`ltr` or `rtl`, from CLDR).
- **INS-088** Display of numbers, dates, currencies, units and plural forms MUST use CLDR data for the selected locale. Input MUST accept that locale's decimal and grouping separators and native digits, and MUST normalise them before validation. Records MUST hold only the locale-independent value (WIRE-052).
- **INS-089** `CheckCompatibility` MUST report, for each declared language, whether the runtime can render it (script, font and direction, from `ControlCatalogue`). A runtime MUST offer only languages it can render, and MUST reject an instrument none of whose languages it can render.

### 5.10 Schema versions and compatibility

- **INS-090** The instrument schema is versioned with semantic versioning, independently of `apiVersion`. A major version changes for breaking changes; a minor version adds control types, options, rule functions or check types.
- **INS-091** An instrument MUST declare the range it needs as `spec.schema: "^<major>.<minor>"`.
- **INS-092** A runtime implementing schema `M.m` MUST accept an instrument requiring `^M'.m'` only if `M == M'` and `m >= m'`. Otherwise it MUST reject the instrument before rendering, with `IncompatibleSchemaRange`.
- **INS-093** The factory MUST NOT build a bundle whose instrument is incompatible with the schema version the registered runtime reported at registration ([Distribution](./distribution.md)).

### 5.10a Fingerprints ([ADR 0027](../../explanation/adr/0027-salted-instrument-fingerprints.md))

- **INS-100** Every published instrument version MUST be identified by its salted fingerprint (WIRE §instrument-fingerprint).
- **INS-101** `metadata.name` and `metadata.version` MUST be treated as labels only and MUST NOT be used to identify, look up or join instruments.
- **INS-102** Two instruments with the same name, version or contents MUST be treated as different instruments when their fingerprints differ.
- **INS-103** The runtime MUST recompute an instrument's fingerprint from its salt and canonical bytes and MUST reject the instrument if it doesn't match the fingerprint the bundle names.
- **INS-104** Interfaces SHOULD show the short fingerprint beside the instrument's name.

### 5.11 Descriptive metadata ([ADR 0032](../../explanation/adr/0032-standard-survey-elements.md))

- **INS-110** An instrument MUST declare `spec.title` (localised) and `spec.administration`: `interviewer` (a collector asks and records), `self` (the subject answers on the device) or `both`.
- **INS-111** An instrument SHOULD declare `spec.description` and `spec.purpose` (localised) and `spec.publisher` (the authority's name as it should appear to subjects).
- **INS-112** An instrument that is derived from, or reproduces, another instrument MUST declare `spec.derivedFrom: [{title, version?, citation, url?}]` and MUST declare `spec.copyright` (a notice and a licence identifier, SPDX where one exists) when the source is under copyright.
- **INS-113** Runtimes MUST make the title, publisher and copyright notice available to the collector, and MUST show them to the subject when `administration` is `self` or `both`.

### 5.12 The element tree

- **INS-120** `spec.elements` MUST be a non-empty ordered tree of elements, each with a `kind`: `group`, `question` or `display`. It replaces sections (INS-010).
- **INS-121** A `group` MUST have an `id` (a path segment, INS-012), a localised `label` and at least one child element. It MAY have a `description` and a `referencePeriod` (localised text, for example "in the last 30 days"). The paths of its descendants MUST be prefixed with the group's path.
- **INS-122** Groups MUST NOT nest deeper than 4 levels.
- **INS-123** A `display` element MUST have an `id`, and either localised `text`, `media` (§5.19) or both. It MUST NOT have a control or record anything. Its `role` MUST be one of `instruction`, `note`, `introduction` or `end`.
- **INS-124** Group, question and display elements MAY have a `when` expression (the rule language, §5.5). An element whose `when` is false MUST be treated as hidden by a `skip` rule. Every item inside a hidden group MUST be cleared from the pending record.
- **INS-125** A question or group MAY declare `disabledDisplay: hidden | protected`. `protected` shows the element visibly disabled while its `when` or skip condition hides it. The default MUST be `hidden`.

### 5.13 Repeats

- **INS-126** A group MAY declare `repeat: {over: <code list>}`. Compilation MUST expand it into one instance per code of that list, in the list's order, with instance path `<group path>.<code>`. Codes of a repeated list MUST be valid path segments (INS-012).
- **INS-127** Each instance MUST take its label from the code's label, its description from the code's `description`, and its media from the code's `media`. Instance children MUST keep the group's child structure.
- **INS-128** A repeat group MAY override a child's control options per code with `overrides: {<code>: {<child>: {…}}}`, restricted to a control's `unit`, `unitLabel`, `step`, `min` and `max` (for example `{each}` instead of `[oz_av]`). An override of `unit` MUST also apply to that instance's `data.unit`.
- **INS-129** Rules and field checks declared inside a repeat group MUST use `@` paths for siblings (INS-047). Rules declared outside MAY reference instance paths by their full `$` path.
- **INS-130** *Could, schema 1.1:* a repeat MAY be `{count: <item path>}` or `{open: {max}}` to repeat a group a collected number of times (for example household members). Until schema 1.1 a runtime MUST reject either form (INS-025).

### 5.14 Code lists

- **INS-131** An instrument MAY declare `spec.codeLists: {<id>: {ordered, codes: [{code, label, description?, value?, exclusive?, media?, icon?, concept?}]}}`. `choice`, `multi-choice`, `scale` and repeats MAY reference a list by id with `codes: <id>` instead of inline options.
- **INS-132** A code's `value` MUST be a decimal giving the code's numeric meaning for analysis (for example times per day: `1-2/week` → `0.214`). Only `value()` (INS-048) and the data contract (INS-072) MAY read it. It MUST NOT change what is recorded, which is always the code.
- **INS-133** A code marked `exclusive: true` (for example *none of these*) MUST, when selected in a `multi-choice`, deselect every other code, and MUST be deselected when another code is selected.
- **INS-134** A code list MAY declare `other: {code, label, maxLength}`. Selecting the `other` code MUST require a text answer, recorded atomically at `<path>.other`. In a repeat, an instance whose code is the `other` code MUST record the text that names the item at `<instance path>.other`.
- **INS-137** The `other` code MUST also appear in the list's `codes`. Compilation MUST synthesise, for every question or repeat instance that can record it, a text question at `<path>.other` with `data: {type: string}`, so the data contract describes it (INS-071).
- **INS-135** A `scale` MUST reference an `ordered: true` list, and its steps MUST be the list's codes in order. A layout MUST NOT reorder them (INS-203).
- **INS-136** Codes MUST be unique within a list and MUST be stable across instrument versions: a code whose meaning changes MUST get a new code.

### 5.15 Nonresponse

- **INS-140** A question MAY declare `nonresponse: [dont-know, refused]` (either or both). An instrument MAY set a default with `spec.nonresponse`. Runtimes MUST offer only the declared codes, as distinct actions next to the control, never as options in it.
- **INS-141** A nonresponse MUST be recorded as `{"nr": "dont-know"}` or `{"nr": "refused"}` (WIRE-052), MUST clear any value of the item, and MUST count the item as answered in the unanswered count ([Collection](./collection.md), COL-036).
- **INS-142** `not-applicable` MUST NOT be entered by anyone. Intake MUST derive it for every item a `skip` or `when` hid at seal time. *Unset* (not asked) MUST remain absent from records (INS-021).
- **INS-143** Nonresponse MUST NOT be encoded as a number, sentinel code or empty value in records or in the data contract.

### 5.16 Text roles

- **INS-150** A question's `label` MUST be the question as asked. A question MAY have a `prefix` (its printed number, for example `10a`), a `shortLabel` (for review summaries and data-contract labels), `help` (shown to whoever answers) and `guidance` (shown to the collector only).
- **INS-151** When `administration` is `self`, runtimes MUST NOT show `guidance`.
- **INS-152** All of these MUST be `LocalisedText` (INS-080).

### 5.17 Units and money

- **INS-160** A numeric control's `unit` MUST be an entry of the standard catalogue or of a referenced extension (INS-235), with a localised `unitLabel` where the entry has no text in the selected language (INS-238). An arbitrary UCUM code or annotation such as `{each}` is not a unit; an authority that needs one declares it in an extension.
- **INS-161** A `number` or `measurement-pair` MAY declare `entryUnits` that the collector may enter instead (INS-229). When it does, the runtime MUST record the value as entered, together with the unit at `<path>.unit`, atomically. No component converts it, and `min`, `max` and `tolerance` are checked in the unit entered (INS-229).
- **INS-162** A `money` control MUST declare `currency` (ISO 4217), and its value MUST be a decimal with at most the currency's minor-unit digits.
- **INS-163** A `stepper`'s value MUST be `start + k × step` for an integer k, within `min`..`max`. `step` MAY be fractional (for example 0.5).
- **INS-164** Evaluating a record (`EvaluateRules`) MUST report a value problem for every recorded value that breaks any constraint of its control: wrong type, a decimal for an `integer` item, a code outside the list, more codes than `max`, a number outside `min`..`max`, a missing or over-long `other` text (INS-134), an entry unit on a control that declares none, and any path the instrument does not have. A runtime MUST refuse to store such a value (it is not written, and the capture is unchanged) and MUST NOT seal while one is held; intake MUST hold a record that carries one.

### 5.18 Concept codes

- **INS-170** Questions, code-list codes and groups SHOULD declare `concept: [{system, code, display?}]` to map them to external terminologies (for example a LOINC code for body weight, or a food-group classification used downstream for diet-quality indicators; the tool carries the mapping and never evaluates it, INS-228).
- **INS-171** Concept codes MUST NOT change validation, rendering or records. They MUST be carried into the data contract (INS-070).

### 5.19 Media

- **INS-180** An instrument MAY declare `spec.media: {<id>: {mediaType, sha256, bytes, alt}}` with PNG, WebP or SVG Tiny images. Elements and codes reference media by id. Media MUST be part of the instrument's canonical bytes, and MUST NOT be fetched from anywhere.
- **INS-181** Every media reference MUST carry localised `alt` text.
- **INS-182** All media in an instrument MUST total at most 8 MiB, and each image at most 1 MiB. SVG MUST be SVG Tiny 1.2 with no scripts, external references or animation.
- **INS-183** An `icon` MAY instead be a single Unicode emoji, rendered as text.

### 5.20 Session-scoped items and randomisation (Could)

- **INS-190** *Could, schema 1.1:* a group MAY declare `scope: session`: its items are answered once per session (for example an equipment check), recorded in a `context` record, and referenced by later records of the session. This needs a WIRE record type and is deferred.
- **INS-191** *Could:* a `choice` or `multi-choice` over an `ordered: false` list MAY declare `randomise: true`. The order MUST be derived from the record ID, and the shown order MUST be reproducible at intake from that ID alone.

### 5.21 Layouts and render plans ([ADR 0033](../../explanation/adr/0033-presentation-layouts.md))

A layout arranges one instrument's elements for presentation. It is published as its own artefact (`kind: Layout`, [Publishing](./publishing.md)) and never changes content.

**Containers:**

| Container | Holds | Meaning |
|---|---|---|
| `step` | Any containers or elements | One stage of navigation, with a localised `title`. Steps are in order. |
| `tabs` | `tab` containers | Sibling groups of the instrument that the collector moves between freely within a step (for example food categories) |
| `tab` | Any containers or elements | One tab, with a localised `title` and optional `icon` |
| `card` | Elements and `row`s | A visually bounded group, with an optional localised `title` and `icon` |
| `row` | Elements | Controls side by side on wide screens, stacked on compact ones |
| `table` | One repeat group | Instances as rows and children as columns, the paper-grid presentation |
| `list` | One repeat group | Instances one per `card` (the item-by-item presentation) |

- **INS-200** A layout MUST be a resource with `kind: Layout`, `metadata.name`, `metadata.version`, `spec.instrument` (the fingerprint of exactly one instrument), `spec.schema` (INS-091) and `spec.steps` (a non-empty list of `step` containers). The authoring form MAY name the instrument by source path; canonicalisation MUST replace it with the fingerprint. An instrument has no salt until it is published ([ADR 0027](../../explanation/adr/0027-salted-instrument-fingerprints.md)), so before publishing a layout MUST bind to the instrument by its unsalted content address (WIRE-011, the hash of the canonical bytes), which is what authoring tools check; a layout in a published bundle MUST name the instrument's salted fingerprint (INS-100), and publishing replaces the one with the other.
- **INS-201** Leaves MUST reference elements by their full path: `{element: <path>}` for one question or display element (a display's path is its parent group's path and its `id`, joined by `.`; a top-level display's path is its `id`), `{group: <path>}` for a group, and `{repeat: <path>, as: table | list}` for a repeat group. A `{group}` leaf MUST be laid out as the default layout lays out that group's subtree (INS-206): its children in tree order, nested groups as `card`s, repeats as `list`.
- **INS-202** Every question of the instrument MUST be placed exactly once, directly or through its group or repeat. Display elements MAY be omitted. Validation MUST fail with `UnplacedQuestion` or `DuplicatePlacement` otherwise.
- **INS-203** A layout MUST NOT carry any text except container `title`s, and MUST NOT override a label, option, option order, unit, rule, nonresponse code or any other instrument content (`ContentOverride`). It MUST NOT set a default, pre-select, highlight or recommend an option.
- **INS-204** A layout MAY set a question's `presentation` only to a value the control allows (§5.3), and MAY set `emphasis: normal | compact` on a container.
- **INS-205** A layout MUST declare `navigation: linear | free` per step. `linear` steps MUST be visited in order, and the collector MAY go back. `free` allows any step. Tabs within a step MUST always be free.
- **INS-206** When a bundle carries no layout for an instrument, `CompileRenderPlan` MUST generate the default layout deterministically: one `linear` step per top-level group (top-level display elements join the step of the group that follows them, or the last step if none follows), `card`s for nested groups, `list` for repeats, and a final review step ([Collection](./collection.md), COL-060).
- **INS-207** A layout MAY declare `windowClass: compact | medium | expanded` (by available width: below 600, 600–839, and 840 or more density-independent pixels). A bundle MAY carry one layout per window class for an instrument. The runtime MUST pick, in order: the layout for its current class; a layout that declares no class; the layout for the nearest smaller class; then the default (INS-206).
- **INS-208** `CompileRenderPlan` MUST be implemented once in the format core (INS-046). Its output MUST be identical for the same instrument, layout, locale and window class on every platform. Platform adapters MUST draw the plan's nodes in order, and MUST NOT regroup, reorder or omit them.
- **INS-209** Every `items` record MUST carry the content address of the layout it was collected with, or the default-layout marker (WIRE-051).
- **INS-214** A layout MUST partition, never permute: the questions it places, read in layout order (steps in order, then containers depth-first, tabs in order), MUST be in the instrument's tree order. Validation MUST fail with `OrderChanged` otherwise.
- **INS-215** Each `tab` of a `tabs` container MUST hold exactly one group of the instrument (as a `{group}` or `{repeat}` leaf, or as containers that place only that group's elements), and the groups of one `tabs` container MUST be siblings, in tree order. Free navigation (INS-205) MUST NOT reach questions outside those groups.

**Choice-load lints.** These apply Hick's law and the survey-methodology evidence on grids. They are advisory: `fieldseal layout lint` reports them, and publishing policy MAY make any of them blocking or change its threshold.

- **INS-210** SHOULD warn when a screen holds more than `maxDecisionsPerScreen` (default 7) questions. The count is exact and advisory:
  - A *screen* is a `step`, or one `tab` of a `tabs` container. A tab is its own screen, and its questions do not count towards the step that holds the `tabs`.
  - A screen's count is the number of questions in its subtree of the render plan that have an input control. Read-only roster items, "other" text inputs and instance-name inputs are not counted.
  - A repeat group counts its questions once for each of its instances in the plan, whether it is drawn as a `list` or a `table`.
  - The count is taken from the plan alone: it counts questions placed, not questions a record leaves unanswered or hidden, so it is the same for every record.

  Because every instance counts, per-instance counting is noisy for long repeats: a repeat of ten instances with two questions each counts twenty, though a `list` shows the collector one card at a time. The lint therefore stays advisory (a warning, never an error), and publishing policy MAY raise `maxDecisionsPerScreen` or leave the finding non-blocking.
- **INS-211** SHOULD warn when a visible `choice` or `multi-choice` shows more than `maxVisibleOptions` (default 9) options without a code-list grouping or search presentation.
- **INS-212** SHOULD warn when a `table` places a `scale` of 7 or more steps on a layout whose `windowClass` is `compact`, or that has none.
- **INS-213** SHOULD warn when a question that a rule hides or protects is placed before the question it depends on.

### 5.22 The tool derives nothing ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **INS-226** No component of Fieldseal (the CLI, factory, portal, runtime, intake, HTML and web renderers, bindings, and the data-contract generator) MUST compute, store or emit a derived value, indicator, score, aggregate or unit conversion. Records, the landed long format and exports MUST carry exactly the value entered, with the code or unit it was entered in. Deriving and converting are the downstream data platform's role.
- **INS-227** A rule expression (§5.5) MUST be used only as a predicate: the condition of a `hard`, `soft` or `skip` rule, or of a field check. An expression's result MUST NOT be displayed, recorded, exported or used as an input to another rule. Validation MUST reject a `derive` rule and a `spec.derived` section with `DerivationNotAllowed`. Arithmetic, `value()` and `lookup()` MAY appear inside a predicate, but no result of any of them MUST ever be stored or emitted as data.
- **INS-228** A mapping from a question or code to a classification (a food item to a food group, a weight to a LOINC code) MUST be expressed only as `concept` codes (INS-170) or an extension concept scheme (INS-242). Concept codes and a code's numeric `value` (INS-132) are metadata, carried unevaluated into the data contract. No component MAY aggregate, sum, score or look them up to produce a value.
- **INS-229** When a collector enters a value in an alternative unit, the value MUST be recorded exactly as entered, with its unit (INS-161, first sentence), and no component MUST convert it. `entryUnits` MUST be written `[{unit, min?, max?, tolerance?}]`, and each bound MUST be declared in, and checked in, the unit entered. The data contract MUST give the unit of every value (INS-072).
- **INS-230** A field check (§5.6) is a quality flag. It MAY compute statistics internally in order to decide whether to raise; those statistics MUST NOT be recorded or exported as data. Only the raised check and the records involved are output (INS-052).

### 5.23 The standard catalogue ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **INS-231** The format core MUST embed a `StandardCatalogue`: a closed document (WIRE-208) with a semantic `version` and a content address (WIRE-011) over its canonical bytes. Every tool build MUST contain every released catalogue of its major version, indexed by content address. A released catalogue MUST NOT change. A minor version MAY only add entries, and codes are stable (INS-136).
- **INS-232** A `measure` entry MUST be `{kind: measure, code, label}`, where `code` is a valid UCUM code (case-sensitive form) and `label` is `LocalisedText`. It MUST NOT have other fields.
- **INS-233** A `household` entry MUST be `{kind: household, code, label, description?}`. The catalogue MUST include `cup`, `tablespoon`, `teaspoon`, `piece`, `slice`, `handful`, `bowl` and `glass`. A household entry MUST NOT carry or imply a size, mass, volume, count or conversion factor, and the schema MUST NOT have a field for one (`ConversionNotAllowed`).
- **INS-234** A `currency` entry MUST be `{kind: currency, code, minorUnits, label}`, with every active alphabetic code of the ISO 4217 amendment the catalogue names. The digits used by INS-162 MUST come from `minorUnits`. An extension MUST NOT add a currency.
- **INS-235** A unit reference (`unit`, each `entryUnits` unit, and a repeat override's `unit`, INS-128) MUST resolve to a `measure` or `household` entry of the pinned catalogue, or to an extension unit written `alias:code` (INS-240). Otherwise validation MUST fail with `UnknownUnit`. The code written is the code recorded and carried in the data contract.
- **INS-236** An instrument MUST pin its catalogue as `spec.uses.catalogue: <content address>`. The authoring form MAY omit it; canonicalisation MUST insert the address of the catalogue the tool validated against. A runtime MUST reject an instrument whose catalogue address it does not hold (`UnknownCatalogue`), and `CheckCompatibility` MUST report it.
- **INS-237** A `measurement-pair` MUST use a `measure` unit. A `money` control MUST use `currency` (INS-162), not `unit`. A `number` or `stepper` MAY use a `measure`, `household` or extension unit; for a `household` or `count` unit, `min`, `max` and `step` apply to the number of that unit.
- **INS-238** A unit's label MUST be the entry's label in the selected language (INS-087). Where the entry has no text in that language, the use site's `unitLabel` MUST be used. Where neither exists, validation MUST fail with `UnitLabelMissing`.

### 5.24 Extensions ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

An extension adds data to what an instrument may refer to. It never adds behaviour.

- **INS-239** An extension MUST be a resource with `apiVersion: fieldseal.dev/v1alpha1`, `kind: Extension`, `metadata.name`, `metadata.version` (semantic version), `spec.metaSchema` (INS-251), `spec.languages` with `spec.defaultLanguage`, and `spec.provides`, which MUST have at least one of `units`, `codeLists` and `conceptSchemes`. It is published as its own artefact ([Publishing](./publishing.md), PUB-122). Its schema is closed (WIRE-208).
- **INS-240** An extension unit MUST be `{code, kind, label, description?, ucum?}`:
  - `code` MUST match `^[a-z][a-z0-9_-]{0,31}$` and be unique in the extension;
  - `kind` MUST be `measure`, `household` or `count`;
  - for `measure`, `ucum` MUST be present and a valid UCUM code that no standard `measure` entry has;
  - for `household` and `count`, `ucum` MUST be absent;
  - no kind MAY carry a size, factor or conversion (`ConversionNotAllowed`);
  - `code` MUST NOT equal the code of a standard `household` entry.
- **INS-241** An extension code list MUST have the shape of INS-131 and MUST satisfy INS-132 to INS-136. Its `id` MUST be unique in the extension, and it is referenced as `alias:id` (`codes: acme:freq9`).
- **INS-242** A concept scheme MUST be `{id, system, version?, label, concepts: [{code, label, parent?}]}`, where `system` is a URI. `parent` MUST form a forest of depth at most 8 with no cycle. A scheme is descriptive and MUST NOT be evaluated (INS-228). A `concept: [{system, code}]` entry whose `system` equals the `system` of a scheme in a used extension MUST name a `code` in that scheme (`UnknownConcept`); any other `system` remains a free external reference (INS-170).
- **INS-243** An extension MUST be additive only. It MUST NOT redefine, shadow or alter a standard catalogue entry, a core schema, a control, a rule function, a text role, a layout or a nonresponse code, and MUST NOT declare or change any constraint (`min`, `max`, `step`, `maxLength`, `required`, `exclusive`, or a limit of any kind). The meta-schema (INS-251) MUST have no field that could express such a change; a document that attempts one fails with `ExtensionLoosens` or, for an unknown field, `UnknownField` (WIRE-211).
- **INS-244** An extension MUST be pure data: no expressions, no `when`, no executable content, no URL to be fetched, and no media. It MUST NOT exceed 256 KiB of canonical bytes or 1000 entries.
- **INS-245** An instrument MUST reference extensions only as `spec.uses.extensions: {<alias>: <content address>}`, where an alias matches `^[a-z][a-z0-9_]{0,15}$`, and refer to an entry as `alias:code`. An undeclared alias is `UnknownExtensionAlias`. A declared but unused alias SHOULD be a lint warning. An extension MUST NOT itself reference another extension (`NestedExtension`), so the dependency closure is one level deep. The addresses are part of the instrument's canonical bytes and therefore of its fingerprint (INS-100).
- **INS-246** Validation and compilation MUST resolve each extension address through an `ExtensionResolver` (the artefact registry, a bundle, or for authoring a local file whose address is computed), verify its publication as PUB-071 does, validate it against the meta-schema (INS-251), and check that every entry the instrument uses exists. An unpublished extension MAY be used only to author; an instrument MUST NOT be published, and a factory or runtime MUST NOT use it, unless every extension it references is published and not withdrawn (INS-005).
- **INS-247** The compiled instrument MUST carry the definition of every extension entry it uses, tagged with its extension's name, version and address. The render plan and rule evaluation MUST need nothing else, so a runtime compiles and runs offline from the bundle alone (DIS-074).
- **INS-248** The generated data contract (INS-071) MUST name each extension the instrument uses (name, version, address) and give the definition of each extension unit, code and concept that appears in it.
- **INS-249** An extension MUST be complete in every language it declares (INS-082). An instrument that uses any of its entries MUST declare only languages the extension declares, else validation fails with `ExtensionLanguageGap`.
- **INS-250** A new extension version is a new artefact with a new content address. A minor or patch version MUST NOT remove an entry or change its meaning, and `fieldseal extension diff` MUST report any such change as an error (PUB-124). A major version MAY. An instrument pins one address; moving to a newer extension is a new instrument version with a new fingerprint.
- **INS-251** The extension meta-schema MUST be defined once in the format core as a closed schema with a version `MAJOR.MINOR`, independent of the instrument schema (INS-090). An extension MUST declare `spec.metaSchema: {version, address}`, where `version` is the lowest version defining every construct it uses and `address` is the content address of that version's published JSON Schema. A reader at version `M.n` MUST accept a document declaring `M.m` only if `n >= m`, and otherwise reject it with `IncompatibleMetaSchema` before reading further; it MUST validate against the schema of the declared `M.m`, not of its own newest version; and it MUST reject an `address` that does not match. A minor version adds only optional constructs. Any removal or change of meaning is a new major version. A released version MUST NOT be edited.

### 5.25 Constraints are enforced at entry ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **INS-252** Every constraint an instrument declares on a control MUST be enforced at entry by every UI that renders it, as follows.

  | Constraint | Controls | The UI MUST |
  |---|---|---|
  | `max` | `multi-choice` | refuse a selection beyond `max` (an `other` entry counts as a selection) |
  | `exclusive` | `multi-choice` | deselect the others when an exclusive code is chosen, and deselect it when another is chosen (INS-133) |
  | `min`, `max` | `stepper`, `number`, `money`, `measurement-pair`, `date` | not accept a value outside the range (INS-027), whether typed, pasted, stepped or set by assistive technology |
  | `step`, `decimals`, currency digits | `stepper`, `number`, `money` | not accept a value off the grid or with more digits (INS-163, INS-162) |
  | `maxLength` | `text`, `coded-list-with-other`, `other` text | not accept input beyond the limit, counted in Unicode scalar values after NFC (WIRE-004); an over-long paste MUST be refused with a message, never silently truncated |
  | `other` | code lists with `other` | not complete the selection until the text is given (INS-134) |
  | listed codes | `choice`, `scale`, `coded-list-with-other` | accept only a listed code |
  | `entryUnits` | `number`, `measurement-pair` | accept only a listed unit |
  | not `optional` | every question | show the question as unanswered, and block sealing until the collector acknowledges the count (COL-036) |

- **INS-253** To *refuse* means that the invalid value is never written to the pending record, the control keeps its previous state, and the UI says why using a catalogued message (PLAT-050). Enforcement MUST be in the UI's own input layer for every input path. It MUST NOT rely on the core evaluator rejecting the value later. The core evaluator MUST still enforce every constraint at seal as a second line (INS-046).
- **INS-254** Every control node of the render plan MUST carry its complete constraint set, and an adapter MUST NOT drop a constraint it receives. A runtime's `ControlCatalogue` MUST list the constraint kinds its UI enforces. `CheckCompatibility` MUST report every constraint kind the instrument uses that the runtime does not list, and the instrument is not compatible while that list is non-empty (INS-025).
- **INS-255** The format core MUST ship a shared scenario corpus (`tests/constraints/`): a golden instrument with a question for each constraint in INS-252, and scripted attempts to violate each, with the expected refusal and the unchanged pending record. Every UI (the Android runtime, the `instrument preview` HTML renderer, the web app and every later one) MUST pass it in its own harness (an automated browser or DOM test for the HTML and web UIs, instrumented tests on Android), as the suite `ins-ui-constraints`. A UI MUST NOT ship with a missing or failing scenario.
- **INS-256** For every constraint in INS-252 the corpus MUST include at least: a value exactly at the limit (accepted), one beyond it (refused), the same through paste or programmatic input (refused), and the pending record unchanged afterwards. It MUST include selecting a fifth option where `max` is 4, typing 100 into a field whose maximum is 20, and choosing a second exclusive option. It MUST be run for first collection and for resurvey (INS-023).
- **INS-257** Every rendering of an instrument for people (the HTML adapter, the web device and every runtime renderer) MUST conform to WCAG 2.2 Level AA, on every step, tab and page at the compact and expanded window classes, including: no focused element entirely hidden by sticky content (2.4.11); targets of at least 24 by 24 CSS pixels or with the spacing exception (2.5.8); reflow at 320 CSS pixels without two-dimensional scrolling (1.4.10); no loss of content under text-spacing overrides (1.4.12). Conformance MUST be tested by the axe-core rules for WCAG 2.0, 2.1 and 2.2 A and AA plus checks for those four criteria (`just a11y`), and a release MUST NOT ship with a finding.


### 5.26 Survey folders and translation catalogues (ADR 0041)

- **INS-258** A survey is one folder: `instrument.yaml`, `layouts/<window>.yaml` and `i18n/<lang>.po`, with an optional `README.md`. The folder name MUST equal `survey.name`, and a layout file's stem MUST equal the `window` it declares. A titled layout step or card MUST have an `id:` that is unique in its layout. A file in the folder that is none of these MUST be reported as a warning and never silently ignored. One resolver reads the folder; no other code knows its shape.
- **INS-259** A survey has one catalogue per language, `i18n/<lang>.po`, holding the instrument's texts and every layout's titles. A `msgctxt` MUST be `instrument/<path>` (the text's path in the instrument) or `layout/<window>/<authored id>`, and `msgid` is the English text. A `msgctxt` is never a position.
- **INS-260** A translation report lists, for each catalogue, the source texts that are missing (no entry, or an empty `msgstr`), the entries that are orphaned (their `msgctxt` matches no source text) or stale (their `msgid` differs from the current English text), and each language declared under `translations:` that has no catalogue. A stale entry MUST be treated as missing when the document is expanded: the English text is used and the stale `msgstr` is not applied. A catalogue in which every `msgstr` is empty (the stub `new survey --lang` writes) adds no language to the document; it is a list of what is left to translate. The report is built once per survey over the instrument and layout texts together. All four findings are warnings, and a strict check makes them errors.
- **INS-261** A layout `id:` is authoring-only: it keys a title in the catalogues and MUST NOT be part of the expanded, signed layout, so adding ids changes no layout fingerprint.

## 6. Resources and formats

### 6.1 Instrument

An excerpt of the `school-meals-baseline` example, a food-frequency questionnaire written for this project: part of its demographics, and one food category.

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Instrument
metadata:
  name: school-meals-baseline
  version: 1.0.0
spec:
  schema: "^1.0"
  title: { en: "School meals baseline survey" }
  administration: interviewer
  publisher: Example Authority
  copyright: { notice: "© 2026 Fieldseal contributors", licence: Apache-2.0 }
  languages: [en]
  defaultLanguage: en
  nonresponse: [dont-know]
  consent:
    required: true
    bases:
      - { code: form-seen, label: { en: Signed form seen } }
    statement: { version: 1, text: { en: "I confirm consent was given for this person." } }
    evidence: optional

  codeLists:
    freq-month:                      # used by staples, legumes, vegetables, animal foods
      ordered: true
      codes:
        - { code: never,   label: { en: Never },       value: 0 }
        - { code: m_le1,   label: { en: "≤1/month" },  value: 0.033 }
        - { code: m_2_3,   label: { en: "2–3/month" }, value: 0.083 }
        - { code: w_1_2,   label: { en: "1–2/week" },  value: 0.214 }
        - { code: w_3_4,   label: { en: "3–4/week" },  value: 0.5 }
        - { code: w_5_6,   label: { en: "5–6/week" },  value: 0.786 }
        - { code: d_1,     label: { en: "1/day" },     value: 1 }
        - { code: d_2_3,   label: { en: "2–3/day" },   value: 2.5 }
        - { code: d_gt3,   label: { en: ">3/day" },    value: 4 }
    staples:
      ordered: false
      other: { code: other, label: { en: Other staple }, maxLength: 40 }
      codes:
        - { code: bread,   label: { en: Bread },   description: { en: "White, wholewheat, rolls" }, media: bread }
        - { code: potatoes, label: { en: Potatoes }, description: { en: "Boiled, baked, mashed" } }
        - { code: rice,    label: { en: Rice },    description: { en: "White, brown, fried" } }
        - { code: other,   label: { en: Other staple } }
    sex:
      ordered: false
      codes:
        - { code: male,   label: { en: Male },   icon: "👦" }
        - { code: female, label: { en: Female }, icon: "👧" }

  media:
    bread: { mediaType: image/webp, sha256: "…", bytes: !!binary "…", alt: { en: A loaf of bread } }

  elements:
    - kind: group
      id: about
      label: { en: General information }
      elements:
        - kind: question
          path: sex
          prefix: "2"
          label: { en: Sex }
          control: { type: choice, codes: sex }
          data: { type: code }
        - kind: question
          path: weight
          prefix: "6"
          label: { en: Weight }
          guidance: { en: "Weigh twice. The two readings must match." }
          control: { type: measurement-pair, unit: "[lb_av]", unitLabel: { en: lbs }, entryUnits: [kg],
                     min: 40, max: 300, decimals: 1, tolerance: 0.2 }
          data: { type: decimal, unit: "[lb_av]", concept: [{ system: "http://loinc.org", code: 29463-7 }] }
        - kind: question
          path: money_gets
          prefix: 10a
          label: { en: Do you get spending money? }
          help: { en: Not travel money }
          control: { type: yes-no }
          data: { type: boolean }
        - kind: question
          path: money_per_day
          prefix: 10b
          label: { en: How much money do you get to spend each day? }
          when: '$about.money_gets == true'
          disabledDisplay: protected
          control: { type: money, currency: USD, min: 0, max: 200, step: 5 }
          data: { type: money }

    - kind: display
      id: diet_intro
      role: instruction
      text: { en: "These questions are about foods and drinks over the past month, and yesterday." }

    - kind: group
      id: staples
      label: { en: Staples }
      referencePeriod: { en: in the last month }
      repeat: { over: staples }
      elements:
        - kind: question
          path: freq
          label: { en: How often? }
          control: { type: scale, codes: freq-month, presentation: segments }
          data: { type: code, codeList: freq-month }
        - kind: question
          path: amount
          label: { en: Amount each time }
          when: '@freq != "never"'
          disabledDisplay: protected
          control: { type: stepper, min: 0.5, max: 20, start: 1, step: 0.5, unit: "[oz_av]", unitLabel: { en: oz } }
          data: { type: decimal, unit: "[oz_av]" }
        - kind: question
          path: yesterday
          label: { en: Had it yesterday? }
          control: { type: yes-no, presentation: switch }
          data: { type: boolean }
      rules:
        - id: never-but-yesterday
          kind: soft
          when: '@freq == "never" and @yesterday == true'
          message: { en: "Never, but had it yesterday. Ask again." }
          reasons:
            - { code: unusual-day, label: { en: Unusual day } }
            - { code: not-sure,    label: { en: Not sure } }
  fieldChecks:
    - id: weight-drift
      type: drift
      path: about.weight
      window: 10
      threshold: 2.0
      message: { en: "Weights are rising steadily. Check the scale." }
```

`staples.bread.freq`, `staples.bread.amount` and `staples.bread.yesterday` are the instance paths of the first row. The soft rule is written once and expands to one rule per food (INS-047). The fingerprint is computed by `fieldseal instrument hash school-meals-baseline.yaml`.

### 6.2 Layout

The grouping from the wireframes: demographics as cards on one step, and foods behind category tabs, one card per food.

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Layout
metadata:
  name: school-meals-baseline-expanded
  version: 1.0.0
spec:
  schema: "^1.0"
  instrument: ./school-meals-baseline.yaml   # replaced by the fingerprint when canonicalised
  windowClass: expanded
  steps:
    - title: { en: About you }
      navigation: linear
      contents:
        - card: { title: { en: Basic details }, icon: "🧒", contents: [ { element: about.sex } ] }
        - card: { title: { en: Measurements }, icon: "📏", contents: [ { element: about.weight } ] }
        - card:
            title: { en: Spending money }
            icon: "💵"
            contents: [ { element: about.money_gets }, { element: about.money_per_day } ]
    - title: { en: Foods and drinks }
      navigation: linear
      contents:
        - { element: diet_intro }
        - tabs:
            - tab: { title: { en: Staples }, icon: "🍞", contents: [ { repeat: staples, as: list } ] }
            # … one tab per food category
```

A `compact` variant of the same layout would use `list` throughout. An `expanded` paper-like variant could use `{repeat: staples, as: table}`; lint then warns under INS-212 if it is also used on `compact` screens.

### 6.3 Extension and standard catalogue 

An authority's extension. It adds a custom unit, an authority-specific frequency scale and a food-group concept scheme, and nothing else:

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Extension
metadata: { name: example-diet-units, version: 1.0.0 }
spec:
  metaSchema: { version: "1.0", address: "sha256:…" }
  languages: [en, es]
  defaultLanguage: en
  provides:
    units:
      - { code: sachet, kind: count, label: { en: sachet, es: sobre } }
      - { code: serving-spoon, kind: household, label: { en: serving spoon, es: cuchara de servir } }
    conceptSchemes:
      - id: food-groups
        system: "urn:example:dqq:food-groups"
        label: { en: Food groups, es: Grupos de alimentos }
        concepts:
          - { code: grains, label: { en: Grains, es: Cereales } }
          - { code: dark-leafy-greens, label: { en: Dark leafy green vegetables, es: Verduras de hoja verde oscuro } }
```

An instrument uses it by content address:

```yaml
spec:
  uses:
    catalogue: "sha256:…"            # the standard catalogue this was validated against
    extensions:
      diet: "sha256:…"               # the Extension above, by content address
  # … in a question:
  #   control: { type: number, unit: "diet:sachet", min: 0, max: 20 }
  #   concept: [{ system: "urn:example:dqq:food-groups", code: dark-leafy-greens }]
```

The standard catalogue has the same closed shape, with entries of three kinds:

```yaml
kind: StandardCatalogue
version: 1.0.0
entries:
  - { kind: measure,   code: kg,  label: { en: kilogram } }
  - { kind: household, code: cup, label: { en: cup } }            # no size, no factor
  - { kind: currency,  code: USD, minorUnits: 2, label: { en: US dollar } }
```

## 7. Twelve-factor

- **Config (III):** an instrument is an artefact, not configuration. It is never set through environment variables. Which instruments a deployment uses is in its deployment manifest and factory policy.
- **Build, release, run (V):** instruments are released through publishing, independently of runtime builds. A runtime build fixes only the schema version it supports.
- **Dev/prod parity (X):** the same instrument bytes are used in development, test and production. Only signatures differ, and production trust bundles accept only production publisher keys.
- Other factors don't apply to a data definition.

## 8. Conformance

| Test | Requirements | Command |
|---|---|---|
| Canonicalisation is deterministic and ignores formatting | INS-002, INS-003 | `fieldseal instrument hash` over golden documents |
| Unknown fields, controls and paths are rejected | INS-006, INS-012, INS-025 | `fieldseal instrument validate` over invalid fixtures |
| Rule grammar and bounds | INS-040, INS-041, INS-044 | `fieldseal instrument validate`, `fieldseal conformance run --suite ins-rules` |
| Unset propagation and verdicts match golden vectors (`crates/contexts/instrument/tests/vectors/rules.json`) | INS-041, INS-042, INS-046 | `fieldseal conformance run --suite ins-eval` |
| Field checks raise on golden record sets | INS-050–INS-053 | `fieldseal device simulate --review`, `fieldseal conformance run --suite ins-checks` |
| Compatibility rule | INS-090–INS-093 | `fieldseal instrument validate --runtime-schema 1.2` |
| Lint findings | — | `fieldseal instrument lint` |
| Rendering plan for each locale | INS-080, INS-087 | `fieldseal instrument preview --lang es` |
| Translation completeness, declarations and message variables | INS-082–INS-086 | `fieldseal instrument validate` over invalid fixtures |
| Locale formatting and native-digit input; right-to-left plans | INS-087–INS-089 | `fieldseal conformance run --suite ins-locale`, `fieldseal layout compile --lang ar-XB` |
| Element tree, repeats and relative rules expand deterministically | INS-120–INS-129, INS-047 | `fieldseal instrument compile` over golden documents |
| Code lists: exclusive, other, ordered, numeric values | INS-131–INS-136, INS-048 | `fieldseal conformance run --suite ins-codes` |
| Nonresponse recorded, cleared and derived | INS-140–INS-143 | `fieldseal conformance run --suite ins-nonresponse`, `fieldseal intake replay` |
| Entry units are recorded as entered and nothing is converted; money digits follow the currency | INS-160–INS-163 | `fieldseal conformance run --suite ins-units` |
| Media limits and SVG restrictions | INS-180–INS-183 | `fieldseal instrument validate` over invalid fixtures |
| Layout placement, order and no content overrides | INS-200–INS-205, INS-214, INS-215 | `fieldseal layout validate` over invalid fixtures |
| Render plans identical across platforms; default layout | INS-206–INS-208 | `fieldseal layout compile` golden plans, replayed by each platform's UI suite |
| Choice-load lints | INS-210–INS-213 | `fieldseal layout lint` |
| Records name their layout | INS-209 | `fieldseal export inspect` |
| The tool derives and converts nothing; `derive` is rejected | INS-226–INS-230 | `fieldseal instrument validate` over invalid fixtures; `fieldseal conformance run --suite ins-units` |
| Standard catalogue: pinned, household entries carry no factor | INS-231–INS-238 | `fieldseal unit list`, `fieldseal instrument validate` over invalid fixtures |
| Extensions: schema, additive-only, references, offline compile, versions | INS-239–INS-251 | `fieldseal extension validate`, `fieldseal extension diff`, `fieldseal instrument compile` over golden bundles |
| Constraints refused at entry by every UI | INS-252–INS-256 | `fieldseal conformance run --suite ins-ui-constraints`; each platform's UI suite |
| Survey folders, catalogue contexts and the translation report | INS-258–INS-261 | `cargo test -p fieldseal-adapters-authoring` (`survey_resolver`, `po_entries`, `translation_report`) |
| Interaction rules on a platform UI | INS-020–INS-024, INS-026, INS-027 | Platform UI test suite, with traces checked by `fieldseal export inspect` |

## 9. Open questions

1. Is the drift check's definition (monotonic movement over `window`) enough, or should it compare against a reference measurement that the collector takes at intervals?
2. *Resolved ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md)):* no. The tool computes and records no derived value (INS-226, INS-227); a body-mass index is the data platform's to compute.
3. *Resolved ([ADR 0032](../../explanation/adr/0032-standard-survey-elements.md)):* static repeats over a code list are in 1.0 (INS-126); dynamic repeats are deferred to 1.1 (INS-130).
4. *Resolved ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md)):* household measures are standard catalogue entries with no conversion factors (INS-233), and nothing is converted to grams in the tool (INS-226); an authority's own portion units are extension units (INS-240).
5. Should the choice-load lint thresholds (INS-210–INS-213) start as blocking in publishing policy for `self`-administered instruments, where no collector can compensate?

## 10. References

- [ADR 0005](../../explanation/adr/0005-format-core.md), [ADR 0009](../../explanation/adr/0009-publishing-with-provenance.md), [ADR 0010](../../explanation/adr/0010-declarative-instruments.md), [ADR 0018](../../explanation/adr/0018-dual-write-records.md), [ADR 0019](../../explanation/adr/0019-review-until-clear.md), [ADR 0022](../../explanation/adr/0022-consent-bases.md), [ADR 0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- [ADR 0032](../../explanation/adr/0032-standard-survey-elements.md), [ADR 0033](../../explanation/adr/0033-presentation-layouts.md), [ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md)
- [Wire formats](./wire-formats.md), [Publishing](./publishing.md), [Collection](./collection.md), [Intake](./intake.md)
- [ADR 0034](../../explanation/adr/0034-internationalisation-and-localisation.md); BCP 47 and RFC 4647 (language tags and lookup); Unicode CLDR; Unicode MessageFormat 2; GNU gettext `.po` catalogues; TRAPD (European Social Survey translation guidelines); UCUM (units of measure); ISO 4217 (currencies); SPDX licence identifiers; SVG Tiny 1.2; RFC 2119 and RFC 8174
- HL7 FHIR R5 Questionnaire; XLSForm (ODK); CDISC ODM; DDI practice on nonresponse categories
- DDI Lifecycle 3.3 (`Sequence`, `QuestionConstruct`); FHIR SDC item controls; Blaise; Dillman, Smyth and Christian, *Internet, Phone, Mail, and Mixed-Mode Surveys* (4th ed.)
- Hick (1952), Hyman (1953): choice reaction time ([Hick's law](https://lawsofux.com/hicks-law/)); Tourangeau, Couper and Conrad (2004); Mavletova, Couper and Lebedev (2018), grid versus item-by-item formats in PC and mobile web surveys
