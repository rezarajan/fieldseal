# Examples

Sample resources, authored strictly to the [specs](../docs/reference/spec/README.md). They are the first inputs for the instrument validator, the CLI and the conformance suites.

## Instruments

| File | What it is | Why it is here |
|---|---|---|
| [`instruments/food-intake-baseline.yaml`](./instruments/food-intake-baseline.yaml) | A full port of a paper baseline food, snack and drink questionnaire: general information, then thirteen food categories, each a repeat over a code list with a frequency scale, an amount and a one-day recall. | The first real instrument. It exercises repeats, per-food unit overrides, the two nine-step frequency scales with numeric values, a soft rule written once and expanded per food, measurement pairs with an entry unit, `money`, conditional questions, roster-read items, display elements, field checks and consent. |
| [`instruments/household-water-access.yaml`](./instruments/household-water-access.yaml) | A short household water, sanitation and hygiene visit, in English and Spanish. | A different domain on purpose, to keep the implementation general. It uses what the first one does not: an exclusive "none of these" code, `date` and `text`, a second currency, `refused` as a nonresponse, concept codes, a lookup table, a derived value, a roster variable inside a label, nested groups and a second complete language. |

The food instrument is deployment content: it names the deployment's own places, foods and programmes, which the specs, code and tools never do. Its copyright notice and licence are placeholders, because the paper form carries a copyright sign but does not name a holder.

Neither instrument is a validated survey tool, and neither is a template to copy blindly. When the Instrument domain lands, `fieldseal instrument validate` runs over both, and the spec notes in the pull request that added them list the places where the spec was ambiguous.

## Layouts

Layouts arrange an instrument's questions for presentation and never change content ([spec §5.21](../docs/reference/spec/instrument.md)).

| File | Window class | Arrangement |
|---|---|---|
| [`layouts/food-intake-baseline.expanded.yaml`](./layouts/food-intake-baseline.expanded.yaml) | expanded | Demographics as cards on step 1; the thirteen categories as free tabs of `list` repeats on step 2. |
| [`layouts/food-intake-baseline.compact.yaml`](./layouts/food-intake-baseline.compact.yaml) | compact | The same cards, then one step per category. |
| [`layouts/household-water-access.compact.yaml`](./layouts/household-water-access.compact.yaml) | compact | Three steps of cards, with titles in both languages. |

## Rosters

Rosters list the subjects of one cohort for a bundle (`fieldseal bundle build --roster`). Each subject has a pseudonymous ID, the text the collector sees, a consent state and `fields`, the values an instrument reads as `roster.<field>`. The bundle builder drops every field the instrument does not reference ([distribution spec](../docs/reference/spec/distribution.md) DIS-013).

| File | For |
|---|---|
| [`rosters/household-water-access.yaml`](./rosters/household-water-access.yaml) | The water instrument: three households, one per consent state. |
| [`rosters/food-intake-baseline.yaml`](./rosters/food-intake-baseline.yaml) | The food instrument: two participants, one with a carried-over status. |

## Reading and checking them

The authoring adapter (`crates/adapters/authoring`) decodes both under strict rules: no duplicate keys, no null, no floats, no anchors, aliases, merge keys or tags (other than `!!binary`), one document per file. A test there decodes every instrument and layout here.

Check them with `fieldseal` (build it with `cargo build -p fieldseal-cli`; the binary is `target/debug/fieldseal`). Every command takes `--json` for one machine-readable result, and exits `1` when there is an error finding:

```sh
fieldseal instrument validate examples/instruments/food-intake-baseline.yaml
fieldseal instrument lint     examples/instruments/household-water-access.yaml
fieldseal instrument hash     examples/instruments/food-intake-baseline.yaml   # sha256:… content address
fieldseal instrument compile  examples/instruments/food-intake-baseline.yaml   # the expanded tree, as JSON

fieldseal layout validate examples/layouts/food-intake-baseline.expanded.yaml --instrument examples/instruments/food-intake-baseline.yaml
fieldseal layout lint     examples/layouts/food-intake-baseline.compact.yaml  --instrument examples/instruments/food-intake-baseline.yaml
fieldseal layout compile  examples/layouts/household-water-access.compact.yaml --instrument examples/instruments/household-water-access.yaml --lang es
```

A layout names its instrument by a path relative to the layout file (`spec.instrument`); `layout validate` checks that it is the same instrument as `--instrument`, by content. `layout lint` takes its thresholds from a publishing policy with `--policy <file>`.

## Previewing them

`fieldseal instrument preview` draws the render plan as one self-contained HTML page: no network requests, inline style, and a small script that only switches steps and tabs. Open the file in any browser.

```sh
fieldseal instrument preview examples/instruments/food-intake-baseline.yaml \
  --layout examples/layouts/food-intake-baseline.expanded.yaml -o dist/preview/food-intake-baseline.expanded.html
fieldseal instrument preview examples/instruments/food-intake-baseline.yaml \
  --layout examples/layouts/food-intake-baseline.compact.yaml -o dist/preview/food-intake-baseline.compact.html
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
| [`scenarios/food-intake-baseline.yaml`](./scenarios/food-intake-baseline.yaml) | The food instrument with consent attested by the collector. |
| [`scenarios/clear.yaml`](./scenarios/clear.yaml) | Clearing with the PIN entered twice, before and after a receipt. |
| [`scenarios/connected-flow.yaml`](./scenarios/connected-flow.yaml) | The device's leg of the connected flow: capture, resurvey, nonresponse, an export file through the in-process intake gate, background upload, the receipt and the clear. `tools/demo-pipeline.sh` runs it after publishing, registering and building a bundle with the real commands. |
