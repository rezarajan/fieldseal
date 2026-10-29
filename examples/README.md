# Examples

Sample resources, authored strictly to the [specs](../docs/reference/spec/README.md). They are the first inputs for the instrument validator, the CLI and the conformance suites.

## Instruments

| File | What it is | Why it is here |
|---|---|---|
| [`instruments/school-meals-baseline.yaml`](./instruments/school-meals-baseline.yaml) | An original school meals survey, written for this project in English and Spanish: general information read from the roster, then how often a pupil has each of a set of generic food groups, in a usual week and a usual day, with an amount and a one-day recall. | The first real instrument. It exercises repeats over a code list, per-item unit overrides, the two nine-step frequency scales with numeric values, a soft rule written once and expanded per item, measurement pairs with an entry unit, `money`, conditional questions, roster-read items, display elements, field checks and consent. |
| [`instruments/household-water-access.yaml`](./instruments/household-water-access.yaml) | A short household water, sanitation and hygiene visit, in English and Spanish. | A different domain on purpose, to keep the implementation general. It uses what the first one does not: an exclusive "none of these" code, `date` and `text`, a second currency, `refused` as a nonresponse, concept codes, a lookup table, a derived value, a roster variable inside a label, nested groups. |

Neither instrument is a validated survey tool, and neither is a template to copy blindly. When the Instrument domain lands, `fieldseal instrument validate` runs over both, and the spec notes in the pull request that added them list the places where the spec was ambiguous.

## Layouts

Layouts arrange an instrument's questions for presentation and never change content ([spec §5.21](../docs/reference/spec/instrument.md)).

| File | Window class | Arrangement |
|---|---|---|
| [`layouts/school-meals-baseline.expanded.yaml`](./layouts/school-meals-baseline.expanded.yaml) | expanded | General information as cards on step 1; the two food blocks as free tabs on step 2. |
| [`layouts/school-meals-baseline.compact.yaml`](./layouts/school-meals-baseline.compact.yaml) | compact | The same cards, then one step per food block. |
| [`layouts/household-water-access.compact.yaml`](./layouts/household-water-access.compact.yaml) | compact | Three steps of cards, with titles in both languages. |

## Rosters

Rosters list the subjects of one cohort for a bundle (`fieldseal bundle build --roster`). Each subject has a pseudonymous ID, the text the collector sees, a consent state and `fields`, the values an instrument reads as `roster.<field>`. The bundle builder drops every field the instrument does not reference ([distribution spec](../docs/reference/spec/distribution.md) DIS-013).

| File | For |
|---|---|
| [`rosters/household-water-access.yaml`](./rosters/household-water-access.yaml) | The water instrument: three households, one per consent state. |
| [`rosters/school-meals-baseline.yaml`](./rosters/school-meals-baseline.yaml) | The school meals instrument: two participants, one with a carried-over status. |

## Reading and checking them

The authoring adapter (`crates/adapters/authoring`) decodes both under strict rules: no duplicate keys, no null, no floats, no anchors, aliases, merge keys or tags (other than `!!binary`), one document per file. A test there decodes every instrument and layout here.

Check them with `fieldseal` (build it with `cargo build -p fieldseal-cli`; the binary is `target/debug/fieldseal`). Every command takes `--json` for one machine-readable result, and exits `1` when there is an error finding:

```sh
fieldseal instrument validate examples/instruments/school-meals-baseline.yaml
fieldseal instrument lint     examples/instruments/household-water-access.yaml
fieldseal instrument hash     examples/instruments/school-meals-baseline.yaml   # sha256:… content address
fieldseal instrument compile  examples/instruments/school-meals-baseline.yaml   # the expanded tree, as JSON

fieldseal layout validate examples/layouts/school-meals-baseline.expanded.yaml --instrument examples/instruments/school-meals-baseline.yaml
fieldseal layout lint     examples/layouts/school-meals-baseline.compact.yaml  --instrument examples/instruments/school-meals-baseline.yaml
fieldseal layout compile  examples/layouts/household-water-access.compact.yaml --instrument examples/instruments/household-water-access.yaml --lang es
```

A layout names its instrument by a path relative to the layout file (`spec.instrument`); `layout validate` checks that it is the same instrument as `--instrument`, by content. `layout lint` takes its thresholds from a publishing policy with `--policy <file>`.

## Previewing them

`fieldseal instrument preview` draws the render plan as one self-contained HTML page: no network requests, inline style, and a small script that only switches steps and tabs. Open the file in any browser.

```sh
fieldseal instrument preview examples/instruments/school-meals-baseline.yaml \
  --layout examples/layouts/school-meals-baseline.expanded.yaml -o dist/preview/school-meals-baseline.expanded.html
fieldseal instrument preview examples/instruments/school-meals-baseline.yaml \
  --layout examples/layouts/school-meals-baseline.compact.yaml -o dist/preview/school-meals-baseline.compact.html
fieldseal instrument preview examples/instruments/household-water-access.yaml \
  --layout examples/layouts/household-water-access.compact.yaml --lang es -o dist/preview/household-water-access.es.html
```

- `--layout` may be given more than once; the one for `--window compact|medium|expanded` is chosen as a runtime would (INS-207). Without `--layout`, the default layout is drawn, ending with a review step.
- `--lang` picks the language by RFC 4647 lookup, falling back to the instrument's default.
- `--answers <file>` takes a YAML or JSON map of item path to recorded value (for example `household.members: 4` or `hygiene.soap_seen: {nr: refused}`). The page then shows those values and only what the rules leave visible, and the rule verdicts are reported (with `--json`, in full).
- `--roster <file>` fills read-only items and `{$roster.…}` texts. Roster contents never go to the terminal, so it needs `-o`.
- `--format plan` prints the render plan as JSON instead of the page.

Without `-o`, the page goes to stdout. `dist/` is ignored by git.

## Scenarios

Scenarios drive `fieldseal device simulate --script <file>` (the simulated device, in memory, with software keys).

| File | What it does |
|---|---|
| [`scenarios/household-water-access.yaml`](./scenarios/household-water-access.yaml) | A day with the water instrument: compact layout, Spanish, a refused nonresponse, a soft rule, pause and resume, a resurvey, review, a receipt, a clear and closing. |
| [`scenarios/school-meals-baseline.yaml`](./scenarios/school-meals-baseline.yaml) | The school meals instrument with consent attested by the collector. |
| [`scenarios/clear.yaml`](./scenarios/clear.yaml) | Clearing with the PIN entered twice, before and after a receipt. |
| [`scenarios/connected-flow.yaml`](./scenarios/connected-flow.yaml) | The device's leg of the connected flow: capture, resurvey, nonresponse, an export file through the in-process intake gate, background upload, the receipt and the clear. `tools/demo-pipeline.sh` runs it after publishing, registering and building a bundle with the real commands. |
