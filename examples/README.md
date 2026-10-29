# Examples

Sample resources, authored strictly to the [specs](../docs/reference/spec/README.md). They are the first inputs for the instrument validator, the CLI and the conformance suites.

## Surveys

A survey is one folder, `surveys/<name>/` (ADR 0041). The folder name is the survey's name.

```text
surveys/<name>/instrument.yaml     the questions, in English
surveys/<name>/layouts/<window>.yaml  one layout for each window class; the file name is the window
surveys/<name>/i18n/<lang>.po      the translations of the instrument and its layouts, one catalogue for each language
surveys/<name>/README.md           optional
```

To start a new one, follow the [tutorial](../docs/tutorials/write-and-publish-your-first-survey.md); [the survey folder](../docs/reference/survey-folder.md) lists which file holds each setting.

A step or card of a layout has an `id:`, which is the key of its title in the catalogues (`layout/<window>/<id>`); an instrument text is `instrument/<path>`. A file in the folder that is none of these is reported as a warning.

| Folder | What it is | Why it is here |
|---|---|---|
| [`surveys/school-meals-baseline`](./surveys/school-meals-baseline) | An original school meals survey, written for this project in English and Spanish: general information read from the roster, then how often a pupil has each of a set of generic food groups, in a usual week and a usual day, with an amount and a one-day recall. Layouts: `expanded` (general information as cards on step 1; the two food blocks as free tabs on step 2) and `compact` (the same cards, then one step per food block). | The first real instrument. It exercises repeats over a code list, per-item unit overrides, the two nine-step frequency scales with numeric values, a soft rule written once and expanded per item, measurement pairs with an entry unit, `money`, conditional questions, roster-read items, display elements, field checks and consent. |
| [`surveys/household-water-access`](./surveys/household-water-access) | A short household water, sanitation and hygiene visit, in English and Spanish. Layout: `compact` (three steps of cards, with titles in both languages). | A different domain on purpose, to keep the implementation general. It uses what the first one does not: an exclusive "none of these" code, `date` and `text`, a second currency, `refused` as a nonresponse, concept codes, a lookup table, a derived value, a roster variable inside a label, nested groups. |

Neither survey is a validated survey tool. Layouts arrange a survey's questions for presentation and never change content ([spec §5.21](../docs/reference/spec/instrument.md)).

## Rosters

Rosters list the subjects of one cohort for a bundle (`fieldseal bundle build --roster`). Each subject has a pseudonymous ID, the text the collector sees, a consent state and `fields`, the values an instrument reads as `roster.<field>`. The bundle builder drops every field the instrument does not reference ([distribution spec](../docs/reference/spec/distribution.md) DIS-013). A roster is named by its cohort, not by a survey: the survey finds its roster through the cohort.

| File | Cohort |
|---|---|
| [`rosters/village-a.yaml`](./rosters/village-a.yaml) | `village-a`, version 3: for the water survey, three households, one per consent state. |
| [`rosters/cohort-a.yaml`](./rosters/cohort-a.yaml) | `cohort-a`, version 1: for the school meals survey, two participants, one with a carried-over status. |

## Reading and checking them

The authoring adapter (`crates/adapters/authoring`) decodes them under strict rules: no duplicate keys, no null, no floats, no anchors, aliases, merge keys or tags (other than `!!binary`), one document per file. A test there decodes every instrument and layout here, and the migration gate (`just migration-gate`) checks that their content addresses have not changed.

Check them with `fieldseal` (build it with `cargo build -p fieldseal-cli`; the binary is `target/debug/fieldseal`). Every command takes `--json` for one machine-readable result, and exits `1` when there is an error finding:

```sh
fieldseal instrument validate examples/surveys/school-meals-baseline
fieldseal instrument lint     examples/surveys/household-water-access
fieldseal instrument hash     examples/surveys/school-meals-baseline   # sha256:… content address
fieldseal instrument compile  examples/surveys/school-meals-baseline   # the expanded tree, as JSON

fieldseal layout validate examples/surveys/school-meals-baseline/layouts/expanded.yaml --instrument examples/surveys/school-meals-baseline
fieldseal layout lint     examples/surveys/school-meals-baseline/layouts/compact.yaml  --instrument examples/surveys/school-meals-baseline
fieldseal layout compile  examples/surveys/household-water-access/layouts/compact.yaml --instrument examples/surveys/household-water-access --lang es
```

A command that takes an instrument accepts the survey folder or its `instrument.yaml`. A layout names its instrument by a path relative to the layout file (`spec.instrument`, always `../instrument.yaml`); `layout validate` checks that it is the same instrument as `--instrument`, by content. `layout lint` takes its thresholds from a publishing policy with `--policy <file>`.

## Previewing them

`fieldseal instrument preview` draws the render plan as one self-contained HTML page: no network requests, inline style, and a small script that only switches steps and tabs. Open the file in any browser.

```sh
fieldseal instrument preview examples/surveys/school-meals-baseline \
  --layout examples/surveys/school-meals-baseline/layouts/expanded.yaml -o dist/preview/school-meals-baseline.expanded.html
fieldseal instrument preview examples/surveys/school-meals-baseline \
  --layout examples/surveys/school-meals-baseline/layouts/compact.yaml -o dist/preview/school-meals-baseline.compact.html
fieldseal instrument preview examples/surveys/household-water-access \
  --layout examples/surveys/household-water-access/layouts/compact.yaml --lang es -o dist/preview/household-water-access.es.html
```

- `--layout` may be given more than once; the one for `--window compact|medium|expanded` is chosen as a runtime would (INS-207). Without `--layout`, the default layout is drawn, ending with a review step.
- `--lang` picks the language by RFC 4647 lookup, falling back to the instrument's default.
- `--answers <file>` takes a YAML or JSON map of item path to recorded value (for example `household.members: 4` or `hygiene.soap_seen: {nr: refused}`). The page then shows those values and only what the rules leave visible, and the rule verdicts are reported (with `--json`, in full).
- `--roster <file>` fills read-only items and `{$roster.…}` texts. Roster contents never go to the terminal, so it needs `-o`.
- `--format plan` prints the render plan as JSON instead of the page.

Without `-o`, the page goes to stdout. `dist/` is ignored by git.

## Scenarios

Scenarios drive `fieldseal device simulate --script <file>` (the simulated device, in memory, with software keys). A scenario names its survey folder (`survey: ../surveys/<name>`) and lists the layouts by window class (`layouts: [compact]`).

| File | What it does |
|---|---|
| [`scenarios/household-water-access.yaml`](./scenarios/household-water-access.yaml) | A day with the water instrument: compact layout, Spanish, a refused nonresponse, a soft rule, pause and resume, a resurvey, review, a receipt, a clear and closing. |
| [`scenarios/school-meals-baseline.yaml`](./scenarios/school-meals-baseline.yaml) | The school meals instrument with consent attested by the collector. |
| [`scenarios/clear.yaml`](./scenarios/clear.yaml) | Clearing with the PIN entered twice, before and after a receipt. |
| [`scenarios/connected-flow.yaml`](./scenarios/connected-flow.yaml) | The device's leg of the connected flow: capture, resurvey, nonresponse, an export file through the in-process intake gate, background upload, the receipt and the clear. `tools/demo-pipeline.sh` runs it after publishing, registering and building a bundle with the real commands. |
