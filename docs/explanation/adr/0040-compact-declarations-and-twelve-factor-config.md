# ADR 0040: Compact declarations for every asset, and twelve-factor configuration

**Status:** Proposed · **Priority:** Must · **Date:** 2026-10-28 · **Supersedes:** the dialect in ADR 0039 §2 (its research, audit and strictness rules stand)

**In one line:** Every declarative asset is plain YAML in a compact dialect of typed keys, with no settings parsed out of free text, and it compiles deterministically to the unchanged canonical artefacts. A survey is written the way an author thinks about it. A deployment manifest says only what it runs and serves, and every per-deploy value is one environment variable.

*The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174 when they appear in capitals.*

## Context

The user reviewed the declarative files and found them far below expectations. Nothing is released yet, so breaking changes are allowed now.

- **Deployments depart from twelve-factor.** `examples/deployments/local-stack.yaml` holds URLs, bind addresses and paths, and repeats them:
  - the factory URL appears as an adapter setting and again under `provisioning`;
  - `/authority/online` appears three times;
  - each port appears twice.

  It also has an `environments:` block, and `deployment render` turns the file into one env file per service. Twelve-factor's config factor says the opposite: config is whatever varies between deploys, it lives in the environment, and its values are independent controls rather than groups named after environments ([12factor.net/config](https://12factor.net/config)).
- **Surveys are far too verbose.** A food-frequency survey in the canonical form ran to about 830 lines plus 117 lines of layouts, because each of its 13 food categories repeated the same three questions. A question states its type twice (`control` and `data`). Every label is an `{ en: … }` map. Frequency values are typed by hand (`0.143`).
- **ADR 0039 is not compact enough.** It still needs about 160 lines, because it moves the words into catalogues but keeps the nested structure. The user asked for "much much much more compact".

## Research

- **Twelve-factor config** ([12factor.net/config](https://12factor.net/config)):
  - config is everything that varies between deploys, such as resource handles, credentials and the canonical hostname;
  - it lives in environment variables, each a granular control;
  - it is never grouped into named environments.

  The test of a correct split is that the codebase could be published without exposing a credential.
- **Score** ([score.dev reference](https://docs.score.dev/docs/score-specification/score-spec-reference/), [score-spec/spec](https://github.com/score-spec/spec)): a developer-owned, platform-agnostic workload file.
  - It declares what the workload needs (resources) and nothing about where it runs.
  - Each platform resolves the needs into concrete values (`${resources.db.host}`) through its own implementation (score-compose, score-k8s).

  This is the right split for Fieldseal: the manifest declares, the environment supplies.
- **Resource URLs** (`DATABASE_URL` on Heroku, Rails and Django):
  - one variable per attached resource;
  - the scheme selects the adapter (`postgres://`, `file://`, `pkcs11:`).

  This removes per-adapter configuration blocks entirely.
- **XLSForm and ODK** ([KoboToolbox: managing choices](https://support.kobotoolbox.org/option_choices_xls), [Survey123: multiple choice](https://doc.arcgis.com/en/survey123/desktop/create-surveys/multiplechoice.htm)):
  - one row per question, and choice lists shared across questions;
  - a manual "other" option, with its own text question, is preferred to the `or_other` shortcut because it keeps control of the label, the translations and the constraints.
- **gettext:**
  - the source language is written inline;
  - translations live in per-language `.po` files;
  - `msgctxt` keeps a translation attached to its place when the wording changes.

  With 100 languages, the source file does not grow.
- **ADR 0039's evidence** (HCL, CUE, Dhall, Starlark, Kustomize versus Helm) still holds:
  - generate structure, never text;
  - keep the language total and bounded;
  - make errors point to a line and column.

## Decision

### 1. One dialect for every declarative asset, compiled to unchanged canonical artefacts

The dialect covers surveys, layouts, policies, rosters, extensions, deployment manifests, scenarios and ceremony files.

- **The files are plain YAML.** No anchors, no tags, no templating text. YAML flow style (`{ … }`, `[ … ]`) keeps a declaration on one line where that reads best.
- **Every setting is a typed key with a closed schema.** There are no phrases or micro-syntaxes inside strings. That rules out `"cup 0.5..20 step 0.5"`, `"2 of 3"` and `"A | B"`, which are written as `{ type: stepper, unit: cup, min: 0.5, max: 20, step: 0.5 }`, `{ threshold: 2, of: 3 }` and `[A, B]`.
  - Labels and help texts are plain text.
- **The canonical artefacts do not change.** A compiler expands each file deterministically into the canonical artefact that exists today: the same CBOR, address, fingerprint, signatures and vectors. The kernel and the contexts do not change. Provenance records the source file's digest.
- **`fieldseal expand <file>` prints the full canonical form**, so nothing is hidden.
- **Strictness (ADR 0037) applies.** An unknown key, a wrong type, a value out of range, or a name that resolves to nothing (a list, a field, a unit, a question in `if:`) is an error at its line and column, with a suggestion. A file has one meaning, never a best guess.
- **Conditions and checks are YAML, not plain language.** There is no expression string and no `and` or `or` written as text. A condition is a tree of typed operators, which nest to any depth (they are total: no loops, no recursion):
  - logic: `{ all: [...] }`, `{ any: [...] }`, `{ not: <condition> }`;
  - comparison: `{ eq: [a, b] }`, `{ ne: [a, b] }`, `{ lt: [a, b] }`, `{ le: [a, b] }`, `{ gt: [a, b] }`, `{ ge: [a, b] }`, `{ between: [a, low, high] }`;
  - membership and state: `{ in: [a, [x, y]] }`, `{ is: a }` (a binary item is true), `{ answered: a }`, `{ count: a, ge: 2 }` (selected codes);
  - operands are question ids, codes of the question's list, or numbers. Each is resolved and type-checked against the question it names.

  For example, `{ all: [ { eq: [often, never] }, { is: yesterday } ] }`. Each operator compiles one to one onto the instrument spec's rule language, which stays the canonical form.
- **A JSON Schema, generated from the one schema source, gives editor completion and inline errors** through the YAML language server.

### 2. Surveys: a question is one line

See `0040-examples/school-meals-baseline.survey.yaml`, the whole school meals survey in 162 lines, against about 1,600 lines in the canonical form (`fieldseal instrument compile`). Its two food categories each repeat three questions per food, written once.

- **Line shape.** A question is `id: { type: <control>, <the control's own settings>…, if?, label?, help?, sensitive? }`. Its `if` is a condition (§1).
- **Labels.** The label defaults to the id written as words (`school` → "School"), so many questions need no label.
- **Settings.** Each control type takes exactly the settings that describe how it operates, and no others. They map one to one onto the existing control catalogue:

| `type` | Settings (typed; required in bold) |
|---|---|
| `choice`, `choices` | **`list`**; `max` (choices) |
| `binary` | `labels` (two, true then false; default from `defaults.binary`, for example `[Yes, No]`, `[Agree, Disagree]`, `[Present, Absent]`) |
| `stepper` | **`unit`** (catalogue or extension, ADR 0037), **`min`**, **`max`**, `step` (default 1), `start` |
| `number` | `min`, `max`, `decimals`, `unit` |
| `money` | **`currency`**, `min`, `max`, `step` (an increment, not a grid) |
| `measure-twice` | **`unit`**, **`min`**, **`max`**, **`tolerance`**, `also` (other entry units) |
| `text` | `max-length`, `multiline` |
| `date` | `min`, `max` |
| `scale` | **`scale`** |
| `roster` | **`field`**, `unit` |

- **Lists** are YAML sequences: `sex: [👦 Male, 👧 Female]`.
  - Codes are generated from the source labels (`Upper Valley` → `upper_valley`). The compiler checks every generated code against the previous published version, so a label edit that would change a code is refused unless the code is pinned (`{ Point Lisas: { code: pl } }`).
  - An `other` option always asks for text, with its rules set once in `defaults.other-text`.
- **Scales are generated from structured steps,** such as `{ from: 2, to: 3, per: month }`, `{ more-than: 3, per: day }` and `{ each: { from: 1, to: 7 }, per: week }`. The compiler produces the codes, the plural-correct labels in every language (CLDR), and the definitional per-day values. Nobody types `0.143`.
- **Repeated question sets are declared once.** In a food block, `ask:` lists the questions asked of every food, and `checks:` lists the rules (`{ when: <condition>, soft: <message>, reasons }`).
  - `blocks:` set a reference period and may override `ask:` for their categories.
  - A category is either a mapping from food to its attributes, or `{ foods: [...] }` with attributes shared by all its foods.
- **Concept tags.** A `dqq:` key attaches a concept code from a signed extension. On a category, it applies to every food in that category. These are metadata only; nothing is computed (ADR 0037). The codes in the example are illustrative until the DQQ extension is built.
- **Defaults are set once** in `defaults:`, for example `dont-know: true` and `other-text: { max-length: 40 }`.
- **Translations.** English, the source language, is written inline; every other language is in `i18n/<lang>.po`, with `msgctxt` set to the element's path. Adding a language never touches the survey, and changing an English text marks the existing translations fuzzy instead of orphaning them. ADR 0039 recommended symbolic message ids instead; this ADR changes that.

### 3. Layouts: one line per card or tab

See `0040-examples/school-meals-baseline.compact.layout.yaml`.

- **A step is a section and its presentation.** Cards are a mapping from title to a list of question ids, for example `🛒 School shop: [uses_shop, shop_weekly, shop_buys]`. A food block is `{ tabs: categories, per-page: 3 }`.

The rule of ADR 0033 is unchanged: a layout partitions the survey and never reorders it. `per-page` feeds the paging the web app uses instead of scrolling.

### 4. Deployments follow twelve-factor

See `0040-examples/fieldseal.deploy.yaml` and `.env.example`.

- **The manifest says only what does not vary between deploys:**
  - the authority's name;
  - the artefacts it serves, pinned by digest;
  - the services it runs.

  It holds no URLs, ports, hosts, paths, secrets, environment blocks or adapter configuration. It MUST NOT contain a value that differs between two deploys of the same release.
- **Every per-deploy value is one environment variable, written once.** Every process that needs a value reads the same variable. For example, `FIELDSEAL_FACTORY_URL` is read by the factory (as its public URL), the CLI, the web app and device provisioning.
- **Each process binds `$PORT`.**
- **Secrets are never inline.** They are passed as `…_FILE` paths or through the platform's secret store.
- **Each variable holds one value.** No lists are packed into strings, and no settings ride in query parameters.
- **For keys and state, the attached resource is a URI whose scheme selects the adapter:**
  - keys: `FIELDSEAL_KEYS=file:…` (development only), `pkcs11:`, `awskms:`, `gcpkms:` or `azurekv:`;
  - state: `FIELDSEAL_STATE=file:…` (development only) or `postgres://…`.
- **The identity provider is configured by separate variables:** `FIELDSEAL_OIDC_ISSUER`, `FIELDSEAL_OIDC_CLIENT_ID`, `FIELDSEAL_OIDC_CLIENT_SECRET_FILE` and `FIELDSEAL_OIDC_ACR_VALUES`.
- **The services are reached at** `FIELDSEAL_FACTORY_URL`, `FIELDSEAL_INTAKE_URL` and `FIELDSEAL_LOG_URL`.
- **There are no named environments.** One variable, `FIELDSEAL_TIER` (`development` or `production`), selects ADR 0038's custody floors and the refusal of development-only schemes. It is a safety floor, not a group of settings.
- **`fieldseal deployment render` and the per-service env files are removed.** The manifest is no longer an env generator.
- **`fieldseal config [service]`** lists each service's variables, with type, default, required or not, and which tier refuses which scheme.
- **Every service validates its own variables at start-up** and refuses to run on an unknown `FIELDSEAL_*` variable, or on a missing, empty or malformed value (ADR 0037).
- **The compose stack** reads one `.env` file.

### 5. The other assets

- **Rosters** are `{ roster: { cohort, version }, columns: [...], rows: [[...], ...] }` (`0040-examples/household-water-access.roster.yaml`). Each row is one subject: compact like CSV, typed like YAML. A row whose length or types differ from `columns` is an error.
- **Policies** state only what they tighten, in typed controls: `publishers: { threshold: 2, of: 3 }` and `unattested-devices: { allowed-in: [development] }`. They are checked against the control schema that `fieldseal policy schema` prints (`0040-examples/deployment-default.policy.yaml`).
- **Scenarios and ceremony files** use the same typed form.

### 6. Limits

The dialect is not a programming language: no user-defined functions, no recursion, no I/O, and no clock or randomness. Iteration is limited to "each food in each category", plus scales and lists. This is ADR 0039's ceiling, unchanged.

## Consequences

- **Breaking change.** Every example and the CLI's authoring readers change. The canonical artefacts, wire formats, signatures and vectors do not.
- **The existing examples are migrated** by a one-off converter, checked by `fieldseal expand` producing artefacts identical to today's.
- **The compiler is new code:** schema-driven expansion, code generation from labels and pinning, scale generation, a corpus of invalid documents, and error messages with suggestions.
- **The deployment context gets smaller.** The manifest model, render and environment handling shrink. The services' config readers move to one shared, scheme-based resolver.
- **The tutorial and the stack change.** `just up` reads one `.env`, and the per-service rendered env files go away.

## Open questions

1. **Inline source language with `msgctxt` (recommended), or ADR 0039's symbolic ids?**
2. **Codes generated from labels, pinned on change (recommended), or always written by hand?**
3. **Rosters as `columns` and `rows` in YAML (recommended), or a CSV option too?**
4. **The deployment manifest.** Should it disappear entirely, with the served artefacts becoming a signed release list, or stay as the small file shown? The small file is recommended.

## Specs

[instrument](../../reference/spec/instrument.md) · [deployment](../../reference/spec/deployment.md) · [policy](../../reference/spec/policy.md) · [distribution](../../reference/spec/distribution.md) · [cli](../../reference/spec/cli.md)
