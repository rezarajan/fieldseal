# Write and publish your first survey

You will write a small survey, check it, translate it, and see the checker tell you when a translation goes out of date. The last section points to publishing. You do not need to have read any design record.

**You need** the `fieldseal` command. From the repository root, `nix develop path:. -c cargo build -p fieldseal-cli` builds it as `target/debug/fieldseal`. The commands below say `fieldseal`; use that path, or put it on your `PATH`. Work in an empty folder of your own.

## 1. Start a survey

```sh
fieldseal new survey my-survey --lang es
```

```text
created surveys/my-survey and the roster stub rosters/my-survey-cohort.yaml
next: fieldseal survey check surveys/my-survey
```

The name is lowercase letters, digits and single hyphens. `--lang es` asks for a Spanish catalogue; leave it out if you only need English. The command refuses to overwrite a survey that is already there.

## 2. Look around

```text
surveys/
  .fieldseal/                 the schemas your editor reads
  my-survey/
    instrument.yaml           the questions, rules and answer lists, in English
    layouts/compact.yaml      how the questions are grouped into screens
    i18n/es.po                the Spanish text
    README.md                 what each file is for
rosters/
  my-survey-cohort.yaml       who to interview: outside the survey folder
```

Each kind of setting has exactly one home:

- What is asked, and the rules, are in `instrument.yaml`.
- How the questions are laid out on a screen is in a file in `layouts/`. The file name is the window size (`compact`).
- Translated text is in `i18n/<language>.po`.

The roster is outside the survey folder on purpose. It holds the names of the people to interview, and the folder is what you publish. Open `instrument.yaml` in an editor that understands YAML schemas and it completes keys and flags mistakes as you type: the first line points at `surveys/.fieldseal/survey.schema.json`.

## 3. Check it

```sh
fieldseal survey check surveys/my-survey --roster rosters/my-survey-cohort.yaml
```

```text
surveys/my-survey: no errors, 14 warning(s)
surveys/my-survey/i18n/es.po:4:1: warning INS-260: `instrument/title` has no `es` translation of "My survey"
...
```

There are no errors, so the survey is valid. The warnings are your translation to-do list: each English text still has an empty Spanish line. Without `--lang` the check prints nothing but an advice line.

`survey check` does everything in one pass: it reads the folder, checks every file against the schema, validates the instrument and the layouts, runs the lints, reports translation gaps and, with `--roster`, compares the roster with the fields the survey reads. It exits `1` when there is an error and `0` otherwise.

## 4. Change the survey and read an error

Add a question at the end of `instrument.yaml`, under the three that are there:

```yaml
    - rooms: {type: number, min: 1, max: 20, decimals: 0, label: How many rooms does the home have?}
```

Check again. A new question must be placed on a screen, so the layout complains:

```text
surveys/my-survey/layouts/compact.yaml: error INS-202 at spec.steps: question `about.rooms` is not placed; every question is placed exactly once
```

Fix it in `layouts/compact.yaml`. A layout groups questions and never reorders them, so the new question goes at the end of the last card's `show:` list:

```yaml
      - show: [about.travel, about.remarks, about.rooms]
```

Now break something on purpose. Change `max: 20` to `mx: 20` and check:

```text
surveys/my-survey/instrument.yaml:30:37: error WIRE-211: UnknownField: unknown key (/sections/0/about/elements/3/rooms/mx)
```

The message gives the file, the line and the column, then what is wrong. Put `max` back.

## 5. Translate

Open `surveys/my-survey/i18n/es.po`. Each entry names a text and has an empty translation:

```text
msgctxt "instrument/title"
msgid "My survey"
msgstr ""
```

`msgctxt` says which text it is, `msgid` is the English the translator sees, and `msgstr` is where the Spanish goes. Fill every `msgstr`. Once you translate any of them, Spanish counts as a language of the survey, and the check asks for two more things until you do them: every text must be translated, and the language must be declared. In `instrument.yaml`, replace the commented lines with:

```yaml
translations:
  es: {method: human, reviewed-by: 1}
```

When `survey check` reports no errors and no warnings, the translation is complete. `--strict` turns warnings into errors, which is what you want in a build that must not ship a gap:

```sh
fieldseal survey check surveys/my-survey --strict
```

## 6. Change the English and see a stale translation

Change the title in `instrument.yaml` from `My survey` to `My first survey`, then check.

```text
surveys/my-survey/i18n/es.po:4:1: warning INS-260: `instrument/title` was written against "My survey" and the text is now "My first survey"
```

The Spanish was written for the old words, so the checker does not use it. Because Spanish is declared as a complete language, the check also reports that the title is missing in Spanish (`INS-082`), and it stays an error until you review the Spanish and change the `msgid` line to the new English. A translation never silently describes words nobody wrote any more.

Two other warnings mean something else. *Orphaned* means an entry no longer matches any text (you deleted a question). *No catalogue* means a language is declared under `translations:` and has no `.po` file.

## 7. Publish

Publishing signs the survey and puts it in the register. That step has its own guide, which arrives with the first `just web`; it begins from a survey that passes `survey check --strict`, so you are ready.

## What to read next

- [The survey folder](../reference/survey-folder.md): which file holds each setting, the `msgctxt` grammar and every finding.
- [Examples](../../examples/README.md): two complete surveys to read.
- [ADR 0041](../explanation/adr/0041-survey-source-tree-and-authoring-toolchain.md): why the folder is shaped this way.
