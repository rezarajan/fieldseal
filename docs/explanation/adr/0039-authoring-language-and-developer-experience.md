# ADR 0039: Authoring language and developer experience

**Status:** Superseded by [ADR 0041](./0041-survey-source-tree-and-authoring-toolchain.md) (was: Proposed, INCOMPLETE draft; see "Unfinished") · **Priority:** Should · **Date:** 2026-10-27

**In one line:** Instruments are written in a terse, strictly schema-checked YAML dialect that a deterministic compiler expands (generators, templates, `forEach`, locals, variables, modules, inherited defaults, inferred `data`, automatic numbering, external message catalogues) into the unchanged canonical, signed instrument.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The project lead reviewed the example instruments and found the syntax far too verbose: inline `label: { en: ... }` maps grow without bound with every language; code values such as `{ code: w1, label: { en: "1/week" }, value: 0.143 }` are computed by hand; and the 830-line food instrument is thirteen near-identical blocks. Developers should define surveys in YAML, with an excellent developer experience. The audit is in [authoring-audit](../../reference/authoring-audit.md): **31 findings**.

Binding constraints: the signed artefact stays the canonical, content-addressed CBOR instrument (INS-013a, WIRE); the kernel wire format does not change; ADR 0037 (accepted, on the `adrs` line) requires closed schemas, no anchors, no derivations at runtime, units from the catalogue; ADRs 0032, 0033, 0034 hold unless amended below.

## Research summary (evidence)

- **Misconfiguration.** In Yin et al. (SOSP 2011), 38.1-53.7% of parameter mistakes were illegal values a checker could catch, 12.2-29.7% were cross-value inconsistencies, pure typos were rare, and only 7.2-15.5% of cases produced a message that pinpointed the error; pinpointing cut diagnosis time 3-13x. Xu et al. (SOSP 2013) argue for treating misconfiguration as a defect to design out. https://www.sigops.org/s/conferences/sosp/2011/current/2011-Cascais/12-yin-online.pdf , https://www.eecg.utoronto.ca/~yuan/papers/sosp13-misconfig.pdf . Google's SRE Workbook attributes 31% of outages to configuration pushes: https://sre.google/workbook/postmortem-analysis
- **YAML.** 1.1 booleans (`NO`) and base-60 ints: https://yaml.org/type/bool.html ; 1.2 removed them: https://yaml.org/spec/1.2.2/ ; StrictYAML removes implicit typing, anchors, flow style: https://hitchdev.com/strictyaml/why/implicit-typing-removed/ . Alias expansion is a DoS vector (limits of 128 or 10 000 nodes in libraries): https://symfony.com/cve-2026-45304 , https://omegaconf.readthedocs.io/en/latest/yaml_aliases.html . ADR 0037's adapter already rejects these.
- **Templating.** HCL: `for_each` keys must be known; "always write nested blocks out literally where possible"; locals "obscure where values originate": https://developer.hashicorp.com/terraform/language/expressions/dynamic-blocks , https://developer.hashicorp.com/terraform/language/values/locals . Variable `validation` blocks: https://developer.hashicorp.com/terraform/language/values/variables . HCL string directives exist to build text: https://developer.hashicorp.com/terraform/language/expressions/strings . Helm text-templates YAML (`nindent`, `quote`) and bolts on `values.schema.json`; Kustomize is "free from templates and DSLs": https://helm.sh/docs/howto/charts_tips_and_tricks/ , https://helm.sh/docs/topics/charts/ , https://kubectl.docs.kubernetes.io/guides/introduction/kustomize/ .
- **Expressiveness ceiling.** Dhall is total, with no recursion: https://docs.dhall-lang.org/discussions/Safety-guarantees.html . Starlark is deterministic and hermetic, no `while`, no recursion: https://github.com/bazelbuild/starlark/blob/master/README.md , https://raw.githubusercontent.com/bazelbuild/starlark/master/design.md . Jsonnet is Turing-complete and lists non-termination as a limitation: https://jsonnet.org/articles/design.html . CUE's order-independent merge and conflict-rejecting defaults: https://cuelang.org/docs/concept/the-logic-of-cue/ (an official "not Turing-complete" statement was **not found**; we do not rely on it). Pkl `amends` cannot add undeclared members; `for` generators cannot create non-constant property names: https://pkl-lang.org/main/current/language-reference/index.html . Nickel merge priorities: https://nickel-lang.org/user-manual/merging/ .
- **Survey formats.** XLSForm shares named choice lists, but links them by string across sheets and uses one column per language: https://xlsform.org/en/ , https://docs.getodk.org/form-language/ . SurveyJS separates layout JSON from translation JSON: https://surveyjs.io/form-library/documentation/survey-localization . REDCap matrices repeat the choice string per row: https://linkml.io/linkml-redcap/reference/data_dictionary/matrix_group_name/ . DDI declares category schemes once and references them: https://docs.ddialliance.org/DDI-Lifecycle/3.1/xmlschema/logicalproduct_xsd/elements/CodeScheme.html . Nonresponse is a typed category, not a magic number: https://docs.ddialliance.org/DDI-Codebook/2.5/xmlschema/schemas/codebook_xsd/complexTypes/catgryType.html . Evidence on Blaise, LimeSurvey `.lss` and Likert-library authoring was thin; those parts are unverified.
- **i18n.** gettext `msgctxt` "should be canonical and never changing": https://www.gnu.org/s/hello/manual/gettext/Contexts.html ; English-text msgids orphan translations on wording edits: https://wiki.mozilla.org/Special:MobileDiff/144179 ; `Plural-Forms` C expressions have documented quirks: https://www.gnu.org/software/gettext/manual/html_node/Plural-forms.html ; Weblate supports key-based ("monolingual") PO: https://docs.weblate.org/en/latest/formats.html . MF2 is CLDR-stable, but **Unicode defines no resource-file format**; the W3C draft is unratified: https://github.com/unicode-org/message-format-wg/blob/main/spec/syntax.md , https://w3c.github.io/message-resources/ . XLIFF 2.1 is a "lossless interchange format": https://docs.oasis-open.org/xliff/xliff-core/v2.1/xliff-core-v2.1.html . Fluent has its own selector syntax, so it duplicates ADR 0034's MF2 choice: https://projectfluent.org/ . Locale fallback chains (Android, Chrome, Java): https://developer.chrome.com/docs/extensions/reference/api/i18n .
- **Error messages.** Elm and Rust: show the user's source, one standalone primary message, a stable code, graded suggestions: https://elm-lang.org/news/compiler-errors-for-humans , https://rustc-dev-guide.rust-lang.org/diagnostics.html . Novices misread highlights unless the message names the highlighted term: https://cs.brown.edu/~sk/Publications/Papers/Published/mfk-mind-lang-novice-inter-error-msg/paper.pdf . The benefit of schema-driven editor completion is **unmeasured**; only vendor documentation exists (yaml-language-server: https://raw.githubusercontent.com/redhat-developer/yaml-language-server/main/README.md ).
- Cognitive Dimensions (Green and Blackwell): repeated blocks show diffuseness and repetition viscosity: https://www.cl.cam.ac.uk/~afb21/CognitiveDimensions/CDtutorial.pdf (the mapping to YAML duplication is our inference).

## Options and decisions

| Question | Options | Decision |
|---|---|---|
| Surface syntax | Keep canonical-shaped YAML; a new DSL; **a YAML dialect over the same parsed tree** | Dialect. Authors "just use YAML" and the existing strict adapter, JSON Schema and editors still apply |
| Reuse mechanism | Text templating (Helm); **structural templating over the parsed tree** (Kustomize/Pkl/CUE-like); general language (Jsonnet, KCL) | Structural templates, `forEach`, locals, variables, modules |
| Ceiling | General language; **total, bounded, hermetic** | See "Expressiveness ceiling" |
| String directives `%{ for }`, `%{ if }` | Adopt; **reject** | Reject. They exist to build text. Our output is a tree (use `forEach`), and ADR 0034 forbids building sentences by concatenation; MF2 `.match` and `.local` do conditional text. `${}` is kept for scalar interpolation only |
| Catalogue container | gettext PO with MF2 bodies; MF2 messages in our own YAML; Fluent | **PO container, symbolic msgids, MF2 bodies** (recommended). Reasons: translators' tools (Poedit, Weblate monolingual PO) and `msgmerge`-style update/fuzzy workflow exist; per-entry comments carry translator notes; Unicode defines no MF2 file format to adopt. Costs: three lines per message (about 660 lines for this survey's English), a strict PO reader to write, and `Plural-Forms` is ignored (plurals live in MF2 `.match`, validated against CLDR). Runner-up: MF2 in strict YAML (denser, reuses the existing adapter, no tool ecosystem). No `.mo` step: catalogues are resolved at compile time |
| msgid | English text; **stable symbolic key derived from the definition site** | Symbolic (gettext's own guidance on canonical contexts; Mozilla's experience) |
| Translator exchange | Replace XLIFF; **keep XLIFF 2.1 as an exchange export** of the PO catalogues, with unit ids equal to the msgids (today they are JSON Pointers, which break on reordering) | Keep |
| Inline wording | **None** in instrument or layout | Instruments hold structure only |

## Decision

### 1. Architecture

A source tree (`fieldseal.yaml` manifest, instrument, layouts, modules, `i18n/<lang>/<domain>.po`) is compiled by `fieldseal` to the canonical instrument and layouts. The compiler is a pure function of the files, the `--var` values, the compiler version and the pinned CLDR version, and MUST produce byte-identical output for equal inputs. Templates, loops, generators and catalogues are resolved at compile time and leave no trace in the canonical form. Provenance (PUB-138) lists every source file, catalogue and module by digest, plus the variable values, compiler version and CLDR version. The kernel wire format is unchanged. Compiled languages remain complete (INS-082): a draft language is not compiled.

### 2. The dialect (see `0039-examples/`)

- **Elements:** `question: id`, `group: id`, `display: id`, `scope:` (a path-transparent group that adds `when`/defaults to children). Control as key: `choice: sex`, `multiChoice: {...}`, `yesNo: switch`, `stepper: {...}`. No `kind:`, `path:` or `control: {type:}`.
- **`data` inferred** from the control (choice to code and its list; multi-choice to codes; stepper and number to decimal or integer with the control's unit; money; text; yes-no to boolean; date). `sensitivity` and `concept` sit on the question. Roster items state `type`.
- **Defaults and inheritance:** `defaults` at instrument, group or scope; narrowest wins; inheritable: `disabledDisplay`, `nonresponse`, `optional`, per-control options. `when` composes with `and`. Items with `roster:` have no nonresponse.
- **Rule expressions:** bare lexical names (siblings, then ancestors) replace `$path`/`@name`; code string literals are checked against the item's code list with did-you-mean; the compiler rewrites to the INS-040 grammar, which is unchanged.
- **Numbering:** `numbering: auto`; `number: none`; `part: true` joins the previous question as 10a, 10b.
- **Generators:** `scales` with `frequency` (counts per period; codes, labels and values generated; value = count or band midpoint divided by period days (day 1, week 7, month 30), rounded half-even to `precision` places, trailing zeros dropped; `over` requires an explicit `assume`) and `numeric` (from, to, step, anchors). `other: {maxLength}` appends the `other` code and its synthesised question once. The generated values for the two food ladders reproduce every value in the current files (checked).
- **Templates and iteration:** `templates` with typed, closed `params` (types: id, string, integer, decimal, bool, enum, codeList, scale, preset, overrides, list, object); `use` and `with`; `forEach` over a list, a map, a code list, `range(a,b)` or (layouts) `children(path, kind)`; `include:` for compile-time conditionals (named apart from the runtime `when`); `locals`; `variables` with type, default and `validation`; `modules` and `imports` of local files only. Remote modules are vendored by `fieldseal source vendor` into a digest-pinned `fieldseal.lock`; compile does no I/O beyond the tree.
- **Reuse versus extensions (ADR 0037):** a module is source composition, expanded away; an Extension is a signed published artefact. Use an Extension when governance and signing of a shared list are needed.
- **Layouts:** `in:` base paths, `items:` lists and `a .. b` ranges (order checked, INS-214), `forEach` over `children()`, shared fragments in layout modules, step and tab titles defaulting to the placed group's label.
- **Messages:** keys are derived from the definition site: `<path>.label|help|guidance|description|text`, `codes.<list>.<code>.label`, template-internal texts under `<template>.…` (shared by every instance), except a template root's `label`, keyed at the instance path. Optional text roles are declared with `texts: [help]`. Compile-time arguments inside messages use `$arg.<name>`; runtime variables stay as INS-084. Plurals and selection are MF2 `.match` evaluated with CLDR at compile time for generated labels.
- **Catalogues:** `i18n/<lang>/<domain>.po`; `i18n/<domain>.pot` generated; lookup falls back region to language to default (RFC 4647) for sparse regional overlays (`es-419`); each non-default entry carries `#. en: <source wording>` and goes `#, fuzzy` with `#| ` the old source when it changes. Unknown, missing and orphaned keys are errors with did-you-mean.
- **Tooling:** `fieldseal i18n init|extract|update|check|hoist` (hoist migrates inline maps), `instrument expand` prints the expanded canonical-shaped form, `fieldseal schema` emits JSON Schema; `fieldseal xliff export|import` is the translator exchange.

### 3. Expressiveness ceiling

The compile-time language is total and bounded: no user functions or recursion (templates MUST NOT instantiate themselves, directly or not, checked on the static call graph); `forEach` only over finite compile-time collections; at most 3 nested loops; at most 10 000 expanded elements and 1 000 iterations per loop; closed built-in functions (`length`, `keys`, `range`, `children`, `concat`, `lookup`), all total and pure; exact decimal arithmetic; no I/O, clock, randomness, environment or network; no regular expressions. Rationale: Dhall's totality, Starlark's determinism and hermeticity, Terraform's own warning about overusing dynamic constructs, and Pkl's rule that generators cannot create non-constant names (here: an id from `${}` must still satisfy INS-012 and be unique, else an error). A feature that needs more belongs in a separate tool that emits YAML.

### 4. Strictness

Every construct is checked against a closed schema; unknown keys are rejected inside templates, `with` arguments, presets and `defaults`; no coercion; `${}` strings are parsed and typed at compile time. Every error carries file, line and column from the authoring adapter, a stable code, one standalone sentence, the offending source, an expected-versus-found line and, where possible, a suggestion, and for expanded output the chain of use sites ("expanded from"). Expansion of 10 000 elements or more is `E-EXPANSION-LIMIT`.

### 5. Editor support

One schema source (ADR 0037 §4) generates JSON Schema 2020-12 (closed with `unevaluatedProperties: false`) for the dialect; files begin with `# yaml-language-server: $schema=...`. A language server (follow-up) adds go-to-definition across files, the default-language wording as an inlay hint on each element, and the compiler's diagnostics. The benefit of completion is plausible but unmeasured; we will measure authoring time on the migrated examples.

### 6. Migration of the examples

Rewrite both instruments and all layouts in the dialect (`fieldseal i18n hoist` does the wording). Renames: `d_1` becomes `d1`; `never-but-yesterday` stays kebab; `{each}` becomes household unit `piece` and `{portion_250ml}` becomes `glass` (ADR 0037 forbids annotation units; the 250 ml stays in the description); `lbs` labels come from the catalogue. Scenarios keep full paths and need no change except unit and code renames. Digests in deployments (`digest: "sha256:..."`) move to a generated `deployment.lock`.

### 7. Amendments

- **ADR 0033:** a layout MAY be generated by compile-time `forEach` over the instrument's group tree and may import fragments; the canonical layout is unchanged; partition-not-permute (INS-214) is checked on the expansion.
- **ADR 0034:** translations are authored in per-locale catalogues (PO container, MF2 bodies), compiled into the instrument's `LocalisedText` maps (fingerprint unchanged in form); XLIFF remains the exchange format with msgids as unit ids; a language MAY be `draft`; regional overlays and fallback apply at authoring time only. Runtime `Localisation` artefacts MAY use the same catalogue source (open question).
- **ADR 0037:** `value` on a generated code is definitional metadata produced by compile-time expansion of an author's declaration and shown by `instrument expand`; it is not a runtime derivation. The standard catalogue MAY define authoring aliases (`lb` for `[lb_av]`) that do not appear in compiled output. Closed-schema and no-anchor rules extend to the dialect, catalogues and modules.

## Spec changes (Proposed, ADR 0039)

IDs are free in main and in the stackfix, strict, adrs and webapp workspaces, with a gap of 10 above the highest used (INS 256, CLI 43, PUB 127).

| ID | Text |
|---|---|
| INS-267 | The authoring dialect MUST compile deterministically to the canonical instrument; same source files, variables, compiler version and CLDR version MUST give identical bytes. |
| INS-268 | Every dialect construct MUST be checked against a closed schema; unknown keys MUST be rejected, including inside templates, `with` arguments and presets. |
| INS-269 | Compile-time evaluation MUST be total and bounded as in ADR 0039 section 3 and MUST NOT perform I/O or read the clock, randomness or environment. |
| INS-270 | Scale generators MUST produce codes, labels and values by the rules in ADR 0039 section 2; `over` steps MUST give `assume`. |
| INS-271 | `data` MUST be inferred from the control by the inference table; an explicit `data` MUST NOT contradict it. |
| INS-272 | `defaults` and inheritance MUST apply narrowest-scope-wins; inherited `when` MUST be combined with `and`. |
| INS-273 | Bare names in authoring expressions MUST resolve lexically and ambiguity MUST be an error; compilation MUST emit the INS-040 grammar. |
| INS-274 | Automatic numbering MUST be stable and deterministic and MUST NOT affect paths or the data contract. |
| INS-275 | Message keys MUST be derived from the definition site by the key rules; a missing, unknown or orphaned key MUST be an error. |
| INS-276 | Catalogues MUST be strict PO (UTF-8, NFC, no duplicate msgid, no `msgid_plural`) with MF2 msgstr validated per INS-084. |
| INS-277 | A language marked `draft` MUST NOT be compiled; every compiled language MUST be complete (INS-082). |
| INS-278 | Imports MUST be local files or vendored, digest-pinned modules; the compiler MUST NOT fetch. |
| INS-279 | Compiler errors MUST carry file, line, column, a stable code and the expansion chain. |
| INS-280 | The authoring JSON Schema MUST be generated from the one schema source of ADR 0037. |
| CLI-054 | `instrument expand`, `i18n init|extract|update|check|hoist`, `xliff export|import`, `source vendor`, `schema`. |
| PUB-138 | Provenance MUST list source files, catalogues, modules, variable values, compiler version and CLDR version by digest. |

## Unfinished

This draft was cut short. Not done: spec text is not yet merged into `instrument.md`, `cli.md` and `publishing.md` (IDs reserved above); the worked example is partial (manifest, instrument, layouts present; the `en` and `es` catalogues, `.pot`, line-count comparison and the compile-by-construct walkthrough are missing); the `variables` and `numeric` scale constructs are specified but unexemplified; no compiler was written or run; the dialect examples were only YAML-parsed.

## Consequences

Survey files shrink (the food instrument structure goes from 947 lines including layouts to about 260 before catalogues, which hold the same wording as before). A new language costs one catalogue and no edits to the survey. The cost is a compiler, a PO reader, a schema generator and indirection (wording is in another file), mitigated by editor hints and `instrument expand`. Amends ADRs 0033, 0034 and 0037.
