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

Publishing signs the survey and puts it in the register, so that anyone can check that it is the survey you reviewed. It needs the authority's keys, a trust bundle, a publishing policy and a transparency log. `just web` makes them.

In a second terminal, start the dev loop:

```sh
just web
```

It creates the authority once (under `deploy/local/.state/dev-web/`), starts the log, the factory and the collector stand-in on your machine, publishes the bundled examples and prints the addresses. Leave it running. In the first terminal, from the folder that holds `surveys/`:

```sh
just publish my-survey
```

The command prints each step it runs: `artefact provenance` (who built it and who reviewed it, with a random salt for the survey), `artefact sign` twice (two of the three publisher keys) and `artefact publish` (the entries go into the log). Then it publishes the survey's layouts the same way, tied to the survey you just published. The output ends with the address of the survey:

```text
published my-survey 0.1.0 at sha256:7af2c2757c6d… in 49 ms
```

Open `http://127.0.0.1:8090/publishing`. The page lists the survey with its name, version, kind, address and log index, and the log has new entries.

Three things to know:

- The command keeps its register in files, because it sets `FIELDSEAL_ADAPTERS=files` and `FIELDSEAL_STATE_DIR=deploy/local/.state/dev-web/cli`. Without `files` the CLI keeps the register in memory and forgets everything when the command ends, so a second run would not know the first.
- A name and a version publish once. Run `just publish my-survey` again and it is refused, saying the version is taken. To publish a change, raise `survey.version` in `instrument.yaml` and publish again. The old version stays in the register.
- To start over, stop `just web` and remove `deploy/local/.state/dev-web/`.

The time to record is the time from a passing `survey check` to the address on the last line. [The build notes](../explanation/build-system.md#measured-baselines) have the figure for this machine.

## What to read next

- [The survey folder](../reference/survey-folder.md): which file holds each setting, the `msgctxt` grammar and every finding.
- [Examples](../../examples/README.md): two complete surveys to read.
- [ADR 0041](../explanation/adr/0041-survey-source-tree-and-authoring-toolchain.md): why the folder is shaped this way.
