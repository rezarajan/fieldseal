//! `fieldseal new survey <name> [--lang es,...] [--root <dir>]` (CLI §5, CLI-044): writes a small
//! working survey folder that passes `survey check`, with the schemas an editor reads and a roster
//! stub beside the survey folders, outside the folder that is published.

use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::survey::SurveyTree;
use fieldseal_kernel::schema::DocKind;

use crate::args::Args;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::schema_cmd::schema_text;
use crate::support::{Res, fail, run_command, usage, write};

/// Runs `new <noun>`; `None` if the noun is not one of these.
pub fn run(noun: &str, raw: &[String]) -> Option<u8> {
    match noun {
        "survey" => Some(run_command("new survey", raw, &["--lang", "--root"], &[], survey)),
        _ => None,
    }
}

const INSTRUMENT: &str = "\
# yaml-language-server: $schema=../.fieldseal/survey.schema.json
# @NAME@, a starting point in the compact dialect (ADR 0040). English is written here@TRANSLATED@.
# Run `fieldseal survey check @DIR@` after every change.
survey: {name: @NAME@, version: 0.1.0}
language: en
title: @TITLE@
description: A short interview that shows how a survey is written.
purpose: To learn how a survey is written, checked and published.
administration: interviewer
publisher: Your organisation
copyright: {notice: © 2026 Your organisation, licence: CC-BY-4.0}
@TRANSLATIONS@nonresponse: [refused]
consent: {required: false}
lists:
  travel-modes:
  - {label: On foot, code: walk}
  - {label: By bicycle, code: bicycle}
  - {label: By bus, code: bus}
  - {label: By car, code: car}
sections:
- about:
    group: About the household
    elements:
    - members: {type: number, min: 1, max: 30, decimals: 0, label: 'How many people live in this household?'}
    - travel: {type: choice, list: travel-modes, label: How do most people in the household travel to work or school?}
    - remarks: {type: text, max-length: 300, multiline: true, label: Anything else to note?, optional: true}
";

const LAYOUT: &str = "\
# yaml-language-server: $schema=../../.fieldseal/layout.schema.json
# Presentation only (ADR 0033): partitions the survey, never reorders it. Each step and card has an
# `id:`, which is the key of its title in the catalogues in ../i18n.
layout: {name: @NAME@-compact, instrument: ../instrument.yaml, window: compact}
steps:
- id: household
  title: The household
  contents:
  - card:
      id: people
      title: People
      contents:
      - show: [about.members]
  - card:
      id: travel
      title: Travel
      contents:
      - show: [about.travel, about.remarks]
";

const README: &str = "\
# @NAME@

Each file in this folder has one job:

| File | What it holds |
|---|---|
| `instrument.yaml` | The questions, the rules and the code lists, in English. |
| `layouts/<window>.yaml` | How the questions are laid out on a screen of that size. The file name is the window class. |
| `i18n/<lang>.po` | The translated text for one language. Each entry's `msgctxt` says which text it is. |

`fieldseal survey check @DIR@` reads all of them and reports every problem with its file, line and column.

Three things live outside this folder on purpose, so that nothing private is published with the survey:

- The roster of people to interview: `@ROSTER@`. It holds personal data.
- The deployments that say where the survey runs.
- The policies that say what a deployment allows.
";

const ROSTER: &str = "\
# A roster for @NAME@: the people or households to interview, in one cohort. It is not part of the
# survey folder and is never published with it. Subject IDs are pseudonyms; `display` is the text
# the collector sees when choosing a subject.
cohort: @NAME@-cohort
version: 1
subjects:
  - subject: s-0001
    display: Household 1
    consent: unknown
  - subject: s-0002
    display: Household 2
    consent: unknown
";

/// `new survey <name> [--lang es,...] [--root <dir>]`.
fn survey(args: &Args, out: &mut Outcome) -> Res {
    let name = args.file("new survey")?;
    if !is_name(name) {
        return Err(usage("bad-survey-name", &[("value", name)]));
    }
    let mut languages: Vec<String> = Vec::new();
    for tag in args.values("--lang").iter().flat_map(|v| v.split(',')).map(str::trim).filter(|t| !t.is_empty()) {
        if tag == "en" {
            return Err(usage("lang-is-source", &[]));
        }
        if !is_language(tag) {
            return Err(usage("bad-language", &[("value", tag)]));
        }
        if !languages.iter().any(|l| l == tag) {
            languages.push(tag.to_owned());
        }
    }
    let root = PathBuf::from(args.value("--root").unwrap_or("surveys"));
    let dir = root.join(name);
    let roster = root.join("..").join("rosters").join(format!("{name}-cohort.yaml"));
    for existing in [&dir, &roster] {
        if existing.exists() {
            fail(out, exit::FAILED, "already-exists", &[("file", &existing.display().to_string())]);
            return Ok(());
        }
    }

    let shown = dir.display().to_string();
    let roster_shown = clean(&roster);
    let fill = |template: &str| {
        // A declared language must be complete (INS-082), so the declaration waits, as a comment,
        // until the catalogue is translated.
        let translations: String = languages.iter().map(|l| format!("#   {l}: {{method: human, reviewed-by: 1}}\n")).collect();
        template
            .replace("@NAME@", name)
            .replace("@TITLE@", &title(name))
            .replace("@DIR@", &shown)
            .replace("@ROSTER@", &roster_shown)
            .replace("@TRANSLATED@", &if languages.is_empty() { String::new() } else { "; each other language is in i18n/<lang>.po".to_owned() })
            .replace("@TRANSLATIONS@", &if languages.is_empty() { String::new() } else { format!("# When a catalogue in i18n/ is fully translated, declare its language:\n# translations:\n{translations}") })
    };
    let files = [
        ("instrument.yaml", fill(INSTRUMENT)),
        ("layouts/compact.yaml", fill(LAYOUT)),
        ("README.md", fill(README)),
    ];
    for (file, text) in &files {
        if !write(&dir.join(file), text.as_bytes(), false, out) {
            return Ok(());
        }
    }
    // The schemas the headers point at: the bytes `schema export --out` writes.
    for kind in [DocKind::Survey, DocKind::Layout] {
        let path = root.join(".fieldseal").join(format!("{}.schema.json", kind.name()));
        if !write(&path, schema_text(kind).as_bytes(), false, out) {
            return Ok(());
        }
    }
    if !write(&roster, fill(ROSTER).as_bytes(), false, out) {
        return Ok(());
    }
    // Every current English text goes into each catalogue with an empty translation.
    for language in &languages {
        let path = dir.join("i18n").join(format!("{language}.po"));
        if !write(&path, b"", false, out) {
            return Ok(());
        }
    }
    if !languages.is_empty() && !fill_catalogues(&root, name, &languages, out) {
        return Ok(());
    }
    out.lines.push(msg("survey-created", &[("dir", &shown), ("roster", &roster_shown)]));
    out.lines.push(msg("survey-next", &[("dir", &shown)]));
    out.set("dir", fieldseal_kernel::Value::Text(shown));
    Ok(())
}

/// Writes each catalogue with every source text as a `msgid` and an empty `msgstr`. The resolver
/// names the texts a catalogue lacks, so the stubs list exactly what it will ask for.
fn fill_catalogues(root: &Path, name: &str, languages: &[String], out: &mut Outcome) -> bool {
    let loaded = SurveyTree::open(root).and_then(|t| t.survey(name)).map_err(|e| vec![e]).and_then(|s| s.load());
    let report = match loaded {
        Ok(l) => l.translation_report,
        Err(errors) => {
            fail(out, exit::INTERNAL, "write-failed", &[("file", &root.join(name).display().to_string()), ("reason", &errors[0].to_string())]);
            return false;
        }
    };
    for language in languages {
        let mut po = format!("# {language} for {name} 0.1.0. Fill in each msgstr; an empty one counts as not translated.\n# msgctxt is `instrument/` and the text's path in the survey, or `layout/<window>/<id>` for a layout title.\n");
        for f in report.iter().filter(|f| &f.language == language) {
            if let Some(text) = &f.new_text {
                po.push_str(&format!("\nmsgctxt \"{}\"\nmsgid \"{}\"\nmsgstr \"\"\n", quote(&f.msgctxt), quote(text)));
            }
        }
        if !write(&root.join(name).join("i18n").join(format!("{language}.po")), po.as_bytes(), false, out) {
            return false;
        }
    }
    true
}

fn quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// A survey name: lowercase letters, digits and single hyphens, starting with a letter.
fn is_name(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase()) && !s.ends_with('-') && !s.contains("--") && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A language tag as `translations:` keys it: letters, then subtags joined by hyphens.
fn is_language(s: &str) -> bool {
    let mut parts = s.split('-');
    parts.next().is_some_and(|p| (2..=3).contains(&p.len()) && p.chars().all(|c| c.is_ascii_lowercase())) && parts.all(|p| (1..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// `my-survey` as `My survey`.
fn title(name: &str) -> String {
    let words = name.replace('-', " ");
    let mut chars = words.chars();
    chars.next().map(|c| c.to_ascii_uppercase().to_string() + chars.as_str()).unwrap_or_default()
}

/// `surveys/../rosters/x.yaml` as `rosters/x.yaml`.
fn clean(path: &Path) -> String {
    let mut parts: Vec<std::path::Component> = Vec::new();
    for c in path.components() {
        match c {
            std::path::Component::ParentDir if matches!(parts.last(), Some(std::path::Component::Normal(_))) => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    parts.iter().collect::<PathBuf>().display().to_string()
}
