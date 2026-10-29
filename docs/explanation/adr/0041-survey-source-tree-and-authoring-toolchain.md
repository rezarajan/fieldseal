# ADR 0041: Survey source tree and authoring toolchain

**Status:** Proposed · **Priority:** Must · **Date:** 2026-10-28 · **Supersedes:** [ADR 0039](./0039-authoring-language-and-developer-experience.md) · **Takes over:** sections 2 and 3 of [ADR 0040](./0040-compact-declarations-and-twelve-factor-config.md)

**In one line:** A survey is one folder, and each setting has one home file in it. Translations are gettext `.po` files keyed by stable `msgctxt` paths and authored layout ids. One declarative schema in the format core checks every authoring document and generates the editor's JSON Schema. `fieldseal new survey` and `fieldseal survey check` give an author a working start and one list of everything wrong. Moving the examples into this shape changed no content address.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

ADR 0040 made surveys compact. It left four things open that a newcomer meets in the first hour:

- **Where does a setting live?** The examples were spread over `examples/instruments/`, `examples/layouts/` and two translation trees. An author could not tell which file to edit, and each loader in the code base knew its own paths.
- **What does a translation key mean?** Layout keys were positions (`steps.1.contents.0.card`), so moving a card orphaned its translation without a sign. ADR 0039 proposed short symbolic ids, which hide the sentence from the translator and give no sign that the English text changed.
- **What does the schema say?** The checks lived in about 1,250 lines of hand-written code, and no schema existed for an editor, so a typo was found late and with a poor message.
- **How do I start?** There was no scaffold and no tutorial.

Binding constraints: the signed artefact stays the canonical, content-addressed CBOR instrument; no wire format changes; ADRs 0032, 0033, 0034 and 0037 hold.

## Decision

### 1. A survey is a folder with one home file for each setting

```text
surveys/<name>/instrument.yaml      content, rules and lists
surveys/<name>/layouts/<window>.yaml  presentation, one per window class; the file name is the window
surveys/<name>/i18n/<lang>.po       translated text, one catalogue per language
surveys/<name>/README.md            optional
```

The folder name is the survey name and MUST equal `survey.name`. A layout's file name MUST equal the `window` it declares. A file that is none of these is reported as a warning, so a stray `instrument.yaml.bak` is never ignored silently. A directory whose name begins with a dot is not a survey; `<root>/.fieldseal/` holds the editor schemas.

Files are not merged by content. Merging needs a rule for which file wins and in what order, and file order could change question order and so the signed hash. A fixed shape gives each setting one home and changes nothing signed.

Only one piece of code knows this shape, the survey resolver in the authoring adapter. Callers name a survey and get its documents back.

**Deployments and policies stay outside the folder.** They vary by environment, authority or tenant, not by survey. **Rosters name only their cohort and version** and live in `rosters/<cohort>.yaml`, outside the folder that is published, because they hold personal data and one cohort can serve several surveys. The link from a survey to a cohort is assignment state, not roster content.

### 2. Translations are `.po` files keyed by `msgctxt`

A catalogue is `i18n/<lang>.po`. `msgid` is the English text and `msgctxt` is the text's place, never a position:

```text
msgctxt = "instrument/" path             instrument/lists.water-sources.borehole
        | "layout/" window "/" id        layout/compact/who-lives-here
```

A step or card of a layout that has a title carries an authored `id:`, which is the key of its title. Ids are unique within a layout and are dropped when the layout is expanded, so they are never signed and no layout fingerprint changes.

A catalogue entry whose `msgid` no longer matches the English text is **stale**, and a stale entry is treated as missing, as `msgfmt` treats fuzzy entries: the English text is used and the old translation is not applied. `survey check` reports four findings, all warnings: missing, orphaned, stale and no catalogue. `--strict` makes them errors for CI. A catalogue in which no entry is translated yet adds no language to the document, so the stub that `new survey --lang` writes is a list of work and does not stop the survey from passing.

`.po` is the translation format of the survey tree. The older XLIFF verbs are not part of it.

### 3. One declarative schema checks every authoring document

The format core holds a table that declares each authoring key once: its path, type, whether it is required and a line of documentation. The decoder validates against the table, and `fieldseal schema export --kind survey|layout` generates the editor's closed JSON Schema from the same table, so the two cannot drift. A failure carries the file, an RFC 6901 pointer, the line and column and one of the six kinds of WIRE-211. `--kind survey` covers `instrument.yaml` and `--kind layout` covers `layouts/*.yaml`.

The export is deterministic: sorted keys, two-space indent and one final newline. Its content address is the SHA-256 of exactly those bytes.

### 4. The authoring commands

- `fieldseal new survey <name> [--lang es,...] [--root <dir>]` writes a working survey that passes `survey check` before it is edited, with every list item's answer code written out (so reword a label and the code stays), a layout with ids, a catalogue for each language, a README, the two editor schemas and a roster stub outside the folder. It refuses to overwrite.
- `fieldseal survey check <dir> [--roster <file>] [--strict]` runs the resolver, the schema check, instrument and layout validation and lint, and the translation report in one pass, with one list of findings. With a roster it compares the fields the roster supplies with the fields the instrument reads.
- `fieldseal survey list` names each survey, its version, languages and layout windows.

### 5. The move changed no address

The examples moved into this shape in one commit. A golden set recorded, before the decoder was rewritten, each example's expanded document, content address, and (under pinned salts) instrument fingerprint and bound layout addresses. `just migration-gate` recomputes them through the resolver and compares. The golden set was not edited by the move, so the move changed no address.

## Alternatives considered

- **Merge files by content.** Rejected: no rule for precedence or order, and an author still could not tell where a setting lives.
- **Short symbolic translation ids (ADR 0039).** Rejected: the translator sees an id instead of the sentence, and a changed English text gives no sign that a translation is out of date.
- **A hand-written JSON Schema kept equal to the decoder by a test.** Rejected: two sources to keep in step. A single table has nothing to drift.
- **Typed structs with a schema derive.** Rejected: it replaces the `Value`-tree decoding that the expander and the position table use, which is a larger change on the signed path.
- **Apply a stale translation with a warning, or refuse to expand.** Rejected: the first shows respondents a translation of old wording; the second blocks publication over a text that has an English fallback.
- **A guided survey-builder UI.** Deferred: it would build on the folder and the schema.

## Consequences

- An author has one place for each setting, a start that works, and a list of every problem with its file, line and column.
- Moving a layout card does not orphan its translation, and editing English text shows which translations to review.
- Every example's content address is unchanged, so nothing published needs re-signing.
- ADR 0040 sections 4 and 5 (deployments and the other assets) remain a separate decision.

## Specs

[cli](../../reference/spec/cli.md) (CLI-041, CLI-044 to CLI-046) · [instrument](../../reference/spec/instrument.md) (INS-258 to INS-261) · [wire formats](../../reference/spec/wire-formats.md) (WIRE-209 to WIRE-213) · [survey folder reference](../../reference/survey-folder.md)
