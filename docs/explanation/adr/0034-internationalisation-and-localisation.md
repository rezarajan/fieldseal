# ADR 0034: Internationalisation and localisation are designed in from the start

**Status:** Accepted (2026-10-27, architecture review #67) · **Priority:** Must · **Date:** 2026-10-27

**In one line:** Every component handles any language, script and locale from the first release. This covers instrument text, the runtime's own UI, formatting, right-to-left scripts and translation review, and records note the language each answer was asked in. Deployments add languages without a new release.

> **Note (ADR 0041).** For surveys written in the compact dialect, translations are gettext `.po` catalogues in the survey folder, one for each language, keyed by `msgctxt` ([ADR 0041](./0041-survey-source-tree-and-authoring-toolchain.md)). `fieldseal survey check` reports missing, orphaned and stale entries. The exchange format described under "Exchange with translators" below is unchanged until a later change retires it.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Fieldseal is domain-neutral and deployment-neutral ([ADR 0002](./0002-name-fieldseal.md)), so it will meet many languages. Instruments are often administered in two languages in one interview, and some deployments will use right-to-left or non-Latin scripts. The draft specs covered only part of this:
- localised instrument text with a default language (INS-080);
- codes, not text, in records (INS-081);
- NFC-normalised UTF-8 (WIRE-004).

Nothing covered:
- the runtime's own UI strings;
- number, date and currency formatting, or input in local digits;
- plurals and placeholders;
- text direction and fonts;
- how translations are made and reviewed;
- the language a question was actually asked in.

Retrofitting i18n is expensive: hard-coded strings, concatenated sentences and locale-formatted values spread through code and data. Retrofitting it into signed formats is worse, because a record format without a language field can't gain one for data already collected.

Established practice:
- **Unicode CLDR:** locale data such as plural rules, number and date formats, and collation.
- **Unicode MessageFormat 2:** messages with placeholders and plural or select variants.
- **BCP 47 / RFC 4647:** language tags and lookup fallback.
- **XLIFF 2.1:** exchanging text with translators. (Removed from the toolchain: `.po` is now the single translation format; see [ADR 0041](./0041-survey-source-tree-and-authoring-toolchain.md).)
- **TRAPD:** the cross-cultural survey method of Translation, Review, Adjudication, Pretest and Documentation, used by the European Social Survey. It treats translation as part of instrument design, with its own review.
- **Pseudo-localisation:** catches truncation, concatenation and hard-coded strings before any real translation exists.

## Decision

**Internationalisation (i18n):** what the code must support.
- **Text is never in code.** Every user-facing string in the runtime, portal and CLI MUST come from a message catalogue keyed by stable message IDs, in Unicode MessageFormat 2. Sentences MUST NOT be built by concatenation.
- **Values are locale-free; display is localised.**
  - Records, wire formats and data contracts MUST store values in locale-independent form: codes, decimals, ISO 8601 dates and ISO 4217 amounts.
  - Runtimes MUST format numbers, dates, currencies, units and plurals for display with CLDR data for the active locale.
  - Runtimes MUST accept input in the locale's decimal separator and native digits, normalised before validation.
- **Any script, either direction.**
  - The render plan MUST carry each language's text direction.
  - Platform adapters MUST mirror layouts for right-to-left languages and isolate bidirectional text.
  - A runtime MUST offer only the languages it can render, with fonts for their scripts.
- **Two language choices.** The runtime UI language and the instrument language MUST be selectable separately. The collector MAY switch the instrument language during a capture, for bilingual interviewing.
- **Language is data.** Every `items` record MUST carry the language tags the questions were shown in during that capture, because the language of administration affects answers.
- **Lookup and fallback** follow RFC 4647 lookup down to the instrument's default language. Records note the language actually shown, never the one requested.

**Localisation (l10n):** what deployments supply.
- **Instrument translations are content.** They are part of the instrument and its fingerprint ([ADR 0027](./0027-salted-instrument-fingerprints.md)):
  - every declared language MUST be complete;
  - each MUST declare how it was translated and reviewed;
  - publishing review covers every language, and TRAPD is recommended.
- **Exchange with translators.** Authors MAY keep translations in XLIFF 2.1 files. `fieldseal instrument i18n extract` and `merge` convert between those files and the instrument, before canonicalisation. (Note: XLIFF exchange and these two verbs were removed; `.po` is the single translation format, as [ADR 0041](./0041-survey-source-tree-and-authoring-toolchain.md) records.)
- **Runtime UI translations are artefacts (Should).** A deployment MAY publish a `Localisation` artefact: a message catalogue for one runtime language. It is delivered in bundles, so a new UI language needs no app release.
  - Validation MUST check its placeholders and variants against the runtime's reference catalogue.
  - Messages that state a security outcome, such as a rejected bundle, MUST keep all their placeholders, and the runtime MUST show the message ID beside them, so support can recognise the message in any language.
  - Until a bundle arrives, the runtime uses its built-in languages.
- **Fingerprint words** for registration ([ADR 0013](./0013-registration-via-authority-tokens.md)) MUST be compared from the same word list on both sides. The list is fixed by the registration format, never by the display language, and both sides MUST also show the words' indices as numbers.
- **Data contracts** carry labels and code labels in every language of the instrument, for analysts.
- **Testing:** every component MUST pass its UI tests in a pseudo-locale (`en-XA`: accented and expanded by about 40 %) and a right-to-left pseudo-locale (`ar-XB`).

## Consequences

- One runtime build serves any deployment's languages. New instrument languages arrive with the instrument; new UI languages arrive as published artefacts.
- Analysts can control for the language of administration. Bilingual interviews stay valid.
- Every component needs CLDR data and an MF2 formatter. In Rust that's ICU4X; Android has ICU built in. Each runtime's size grows by its locale data.
- The registration word list stays a single fixed list. Showing the indices covers collectors who can't read it.

## Specs

[instrument](../../reference/spec/instrument.md) §5.9, [platform profiles](../../reference/spec/platform-profiles.md) §i18n, [registration](../../reference/spec/registration.md) REG-023, [wire formats](../../reference/spec/wire-formats.md) WIRE-051, [publishing](../../reference/spec/publishing.md) §1, [distribution](../../reference/spec/distribution.md) DIS-017, [intake](../../reference/spec/intake.md) INT-071, [CLI](../../reference/spec/cli.md)
