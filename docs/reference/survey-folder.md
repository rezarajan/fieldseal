# The survey folder

Where each setting of a survey lives, how translations are keyed, and what `fieldseal survey check` reports. The design is in [ADR 0041](../explanation/adr/0041-survey-source-tree-and-authoring-toolchain.md); the requirements are INS-258 to INS-261 in the [instrument spec](./spec/instrument.md) and CLI-044 to CLI-046 in the [CLI spec](./spec/cli.md). To write one, follow the [tutorial](../tutorials/write-and-publish-your-first-survey.md).

## Which file holds which setting

| Setting | Home | Notes |
|---|---|---|
| Questions, answer lists, rules, consent, the survey's name and version | `surveys/<name>/instrument.yaml` | The folder name MUST equal `survey.name`. |
| Presentation: screens, cards, tabs | `surveys/<name>/layouts/<window>.yaml` | One file for each window class (`compact`, `medium`, `expanded`). The file name MUST equal the `window` the file declares. A layout groups questions and never reorders or changes them. |
| Translated text | `surveys/<name>/i18n/<lang>.po` | One catalogue for each language, for the instrument and every layout together. |
| Notes for the next author | `surveys/<name>/README.md` | Optional. |
| Editor schemas | `surveys/.fieldseal/survey.schema.json` and `layout.schema.json` | Written by `new survey` and `schema export --out`. Not a survey. |
| Cohort and version of the people to interview | `rosters/<cohort>.yaml` | Outside the survey folder, because it holds personal data and a cohort can serve several surveys. A roster names its cohort and version, never a survey. |
| Deployments (where a survey runs) | `deployments/` | Outside the survey folder: they vary by environment. |
| Policies (what a deployment allows) | outside the survey folder | They vary by authority or tenant. |

A file in the survey folder that is none of these is reported as a warning (`stray-file`) and is not read.

## Translation keys

A catalogue entry has three lines:

```text
msgctxt "instrument/lists.water-sources.borehole"
msgid "Borehole or tube well"
msgstr "Pozo entubado"
```

`msgid` is the English text. `msgstr` is the translation, and an empty one means "not translated yet". `msgctxt` is the place of the text and never a position:

```text
msgctxt = "instrument/" path             the text's path in the survey, joined by dots
        | "layout/" window "/" id        the title of a step or card
```

For example `instrument/title`, `instrument/about.members` (a question's label), `instrument/lists.water-sources.borehole` (an answer's label) and `layout/compact/who-lives-here` (a card title). In a layout, a step or card that has a `title:` also needs an `id:`, and that id is the last part of its key. Ids are unique in a layout. They only key the catalogue; they are not part of the signed layout, so adding or renaming one changes no address.

Parts hold no spaces. An entry whose `msgctxt` is outside the grammar is an error (`po-bad-context`), and so is the same `msgctxt` twice (`po-duplicate-context`).

## What `survey check` reports

`fieldseal survey check <dir> [--roster <file>] [--strict]` prints one list. Each finding has an id, a severity (`error`, `warning` or `advice`), a message and where it is: the file, and for a position the line and column. The summary line comes first. The exit code is `1` when there is any error, otherwise `0`.

| Finding | Id | Severity | Meaning |
|---|---|---|---|
| `no-instrument` | CLI-045 | error | The folder has no `instrument.yaml`. |
| `name-mismatch` | CLI-045 | error | The folder name differs from `survey.name`. |
| `window-mismatch` | CLI-045 | error | A layout's file name differs from the `window` it declares. |
| `missing-layout-id` | CLI-045 | error | A titled step or card has no `id:`. |
| `duplicate-layout-id` | CLI-045 | error | Two steps or cards of one layout share an `id:`. |
| `po-syntax`, `po-duplicate-context`, `po-bad-context` | CLI-045 | error | A catalogue is malformed, repeats a `msgctxt` or uses one outside the grammar. |
| `stray-file` | CLI-045 | warning | A file that is none of the expected files. |
| schema findings (`UnknownField`, `MissingField`, `TypeMismatch`, `EnumValue`, `DuplicateKey`, `CoercionRefused`) | WIRE-211 | error | A key or value the schema does not allow, with line and column. |
| decoding errors | INS-002, WIRE-004 | error | The file is not well-formed YAML, or text is not in Unicode normalisation form C. |
| instrument and layout validation | INS-… | error or warning | The same findings as `instrument validate` and `layout validate`: unknown paths, unplaced questions, incomplete declared languages. |
| lint | INS-… | warning or advice | The same findings as `instrument lint` and `layout lint`. |
| missing translation | INS-260 | warning | A source text has no entry, or its `msgstr` is empty. |
| orphaned translation | INS-260 | warning | An entry's `msgctxt` matches no source text. |
| stale translation | INS-260 | warning | An entry's `msgid` differs from the current English. It is treated as missing: the English is used and the old translation is not applied. |
| no catalogue | INS-260 | warning | A language is declared under `translations:` and has no `i18n/<lang>.po`. |
| roster field missing | DIS-013 | error | The survey reads `roster.<field>` and a subject lacks it. The message names the field and the subject's ordinal, not its ID. |
| roster field unused | DIS-013 | advice | The roster supplies a field the survey never reads. The bundle builder drops it. |

`--strict` turns every warning from the resolver, the validation and the translation report into an error, for builds that must not ship a gap. It leaves lint findings as they are: their limits are set by policy.

A catalogue in which every `msgstr` is empty adds no language to the survey; it is a list of what is left to translate. Once one entry is translated, the language counts, must be declared under `translations:`, and must be complete.

## The editor schemas

`fieldseal schema export --kind survey` prints the JSON Schema of `instrument.yaml`, and `--kind layout` the schema of a layout file. Both are generated from the table the decoder checks against, so they cannot disagree. The output is deterministic, and the address printed under it is the SHA-256 of exactly the schema text. `--out <file>` writes the schema alone. `fieldseal schema check <file>` checks one source file against the schema of its kind.
