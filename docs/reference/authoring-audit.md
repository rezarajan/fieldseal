# Authoring audit (input to ADR 0039, Proposed, incomplete)

Paths are relative to the repository root. "Orig" is the first example instrument, a long food-frequency questionnaire in the canonical form. It was removed from the repository and replaced by the original `examples/instruments/school-meals-baseline.yaml`; the line numbers below refer to the removed file and are kept as this audit's record. Impact is H, M or L.

| # | Construct | Example | Why unintuitive or error-prone | Best in class | Fix | Impact |
|---|---|---|---|---|---|---|
| 1 | Inline translations | Orig:20 `title: { en: ... }`; `household-water-access.yaml:16` interleaves `es` | Every language edits every line; file grows with languages; reviewers cannot read one language; diffusenes/viscosity (Green and Blackwell) | gettext per-locale dirs; Android `values-xx`; SurveyJS localization split | Per-locale PO catalogues, manifest-mapped | H |
| 2 | Hand-computed values | Orig:104-125 `value: 0.143` | Arithmetic by hand; changing a ladder means recomputing; typos pass silently | Generators (HCL `range`, CUE comprehensions); DDI separates definition from value | `frequency`/`numeric` scale generators | H |
| 3 | Repeated per-food block | Orig:400-810, 13 blocks of 31 lines | 13 copies; fix one, miss twelve (repetition viscosity) | HCL `for_each` + modules; Pkl classes | `templates` + `forEach` | H |
| 4 | `control`/`data` duplication | Orig:286-287 `codes: sex` and `codeList: sex`; units twice (315, 319) | Stated twice; can disagree (Yin: 12-30% of parameter errors are inconsistencies) | CUE/Pkl derive types from one declaration | Infer `data` from control | H |
| 5 | `kind: question` boilerplate | Orig:271-384 (55 uses) | Discriminator noise; envelope hides the name | HCL block heads | `question: id` | M |
| 6 | `when`/`disabledDisplay` per question | Orig:352-384 (17 `disabledDisplay`) | Repeated; omitting one is silent | Scoped defaults (Nickel/Nix modules) | `scope`, `defaults` | M |
| 7 | Manual `prefix` | Orig:279-381 `prefix: "1"`..`12b` | Renumber on insert; quoting hazard for numbers as text | XLSForm auto, Blaise | `numbering: auto`, `part` | M |
| 8 | Paths: `path` vs `id`, full paths everywhere | Orig:275 vs 406; layouts and scenarios restate `about.weight` | Two names for one idea; no jump-to-definition; typos found late | Lexical scope; LSP | One `question: id`; lexical names; relative paths in layouts | H |
| 9 | Code lists generated | Orig:104, 116 ladders; yes/no/DK | Structure written as data | DDI shared schemes; XLSForm lists | Scale generators, stock structure with keys | M |
| 10 | Nonresponse repeated | Orig:275-324 `nonresponse: []` x4, `[dont-know, refused]` x2 | Empty list on read-only items is noise | DDI/Blaise project-wide DK/RF | Inherit; roster items imply none | M |
| 11 | Units and currency | Orig:315 `"[lb_av]"` plus `unitLabel`; `{each}`; currency per control | UCUM syntax leaks; labels duplicated; annotation units banned by ADR 0037 | Catalogue aliases | Aliases (`lb`), catalogue labels, `defaults` | M |
| 12 | Rule expression syntax | Orig:353 `'$about.money_gets == true'`, 424 `'@freq != "never"'` | Two sigils; quoting; string-typed codes unchecked; `== true` | Lexical names; Elm-style checks | Bare names, checked codes | H |
| 13 | Layouts restate paths | `layouts/school-meals-baseline.compact.yaml:12-16` | Same lists in two layouts; hand-kept in step | HCL `for_each`; modules | `in:`, ranges, `forEach children()`, fragments | M |
| 14 | 830-line instrument | Orig | Review cost, merge conflicts | Modularisation | See all | H |
| 15 | `other` stated twice | Orig:48 and 53 (17 lists) | Same label twice, must agree (INS-137) | Declare once | `other: {maxLength}` | M |
| 16 | Soft-rule reasons repeated | Orig:429-435, x13 | Identical blocks | Defaults | Instrument `reasons` | M |
| 17 | Identifier styles mixed | `bought-foods`, `animal_foods` | Two styles, path regex differs | One lexical rule | Lint | L |
| 18 | Concept triples repeated | `household-water-access.yaml:41-62` | Copy-paste | Scheme aliases | `conceptSystems` | L |
| 19 | XLIFF unit ids are JSON Pointers | `i18n_cmd.rs` (pointer per unit) | Reordering orphans translations | Stable keys (gettext msgctxt) | Symbolic msgids | H |
| 20 | Header envelope per file | every example, 6-8 lines | Boilerplate | Manifest | `fieldseal.yaml` | L |
| 21 | Hand-pasted digests | `deployments/sample.yaml:22` | Human copies sha256 | Lockfiles | `deployment.lock` | M |
| 22 | Stringly config | `sample.yaml:32` `users: "alice=collector:hwk,..."` | Mini-DSL in a string | Typed lists | Typed schema | L |
| 23 | Overrides by nested path | Orig:503-507 | Untyped nesting | Pkl amends | Template `overrides` param | L |
| 24 | Display role verbose | Orig:386-395 | 4 lines | role key | `display: id, role:` | L |
| 25 | Quoting hazards | `prefix: "1"`, `'$...'` | Number-like text must be quoted | Typed schema | Remove sources | L |
| 26 | Layout step titles restate group labels | compact layout:20-50 | 13 titles x 2 layouts | Inherit | Title defaults to label | M |
| 27 | Layout `instrument:` path coupling | layout:9 | Path string | Manifest | Manifest binds | L |
| 28 | Scenario full paths | `scenarios/school-meals-baseline.yaml:34-45` | Verbose | `in:` | Defer | L |
| 29 | Optional texts implicit | `help`, `guidance` inline | Presence is data | Declared slots | `texts: [help]` | L |
| 30 | No expansion view | spec `instrument compile` only | Hidden dependencies after templating | Terraform plan, `helm template` | `instrument expand` | M |
| 31 | `${}` in YAML flow context needs quoting | new | Flow collisions | n/a | Document quoting; lint | L |

Top 10 by impact: 1, 2, 3, 4, 8, 12, 14, 19, then 5/6/10/13/26 (medium group).
