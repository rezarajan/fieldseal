//! `fieldseal survey check|list` (CLI §5, CLI-045, CLI-046): one pass over a survey folder with
//! one findings list. The survey resolver reads the folder; the instrument and layout checks are
//! the ones `instrument validate|lint` and `layout validate|lint` run.

use std::path::Path;

use fieldseal_adapters_authoring::survey::{LoadedSurvey, ResolveError, ResolveKind, SurveyRef, SurveyTree};
use fieldseal_adapters_authoring::{ErrorKind, Format, decode_raw};
use fieldseal_instrument::application::{LayoutLintThresholds, lint_instrument, lint_layout};
use fieldseal_kernel::Value;

use crate::args::Args;
use crate::commands::{Ctx, load_instrument, load_layout};
use crate::composition::{AuthoringTools, LogFormat};
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::roster_check::compare_roster;
use crate::support::{Res, fail, read, run_command, usage};

/// Runs `survey <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    Some(match verb {
        "check" => run_command("survey check", raw, &["--roster"], &["--strict"], check),
        "list" => run_command("survey list", raw, &["--root"], &[], list),
        _ => return None,
    })
}

/// `survey check <dir> [--roster <file>] [--strict]`.
fn check(args: &Args, out: &mut Outcome) -> Res {
    out.strict = args.has("--strict");
    let dir = args.file("survey check")?.trim_end_matches('/');
    let dir = if dir.is_empty() { "/" } else { dir };
    let Ok(canonical) = std::fs::canonicalize(dir) else {
        fail(out, exit::NOT_FOUND, "not-found", &[("file", dir), ("reason", "no such folder")]);
        return Ok(());
    };
    let (Some(root), Some(name)) = (canonical.parent(), canonical.file_name().and_then(|n| n.to_str())) else {
        return Err(usage("not-a-survey-folder", &[("file", dir)]));
    };
    let survey = match SurveyTree::open(root).and_then(|tree| tree.survey(name)) {
        Ok(s) => s,
        Err(e) => {
            resolve_errors(out, dir, &[e], false);
            return finish(out, dir);
        }
    };
    let loaded = match survey.load() {
        Ok(l) => l,
        Err(errors) => {
            resolve_errors(out, dir, &errors, false);
            return finish(out, dir);
        }
    };
    // Warnings and translation findings are warnings; `--strict` makes them errors.
    if let Err(findings) = loaded.clone().strict() {
        resolve_errors(out, dir, &findings, true);
    }
    check_documents(args, out, dir, &survey, &loaded);
    finish(out, dir)
}

/// The instrument, the layouts against it, and the roster.
fn check_documents(args: &Args, out: &mut Outcome, dir: &str, survey: &SurveyRef, loaded: &LoadedSurvey) {
    let ctx = Ctx { tools: AuthoringTools, log_format: LogFormat::Text };
    let file = |p: &Path| format!("{dir}/{}", p.strip_prefix(&survey.dir).unwrap_or(p).display());
    let instrument_file = file(&survey.instrument);
    // Lint findings carry their own severity (INS-210 is an error for a compact layout and a warning
    // for the others) and a policy sets their limits, so `--strict` leaves them as they are; it makes
    // errors of what validation, the resolver and the translation report warn about.
    let strict = out.strict;
    if let Ok(Some(ins)) = load_instrument(&ctx, &instrument_file, out, true) {
        out.strict = false;
        for f in &lint_instrument(&ins.instrument) {
            out.finding(&instrument_file, f);
        }
        out.strict = strict;
        for l in &survey.layouts {
            let layout_file = file(&l.path);
            if let Ok(Some((layout, _))) = load_layout(&ctx, &layout_file, &ins, None, out) {
                out.strict = false;
                for f in lint_layout(&ins.instrument, &layout, LayoutLintThresholds::default()) {
                    out.finding(&layout_file, &f);
                }
                out.strict = strict;
            }
        }
    }
    if let Some(path) = args.value("--roster") {
        check_roster(out, path, &loaded.instrument);
    }
}

/// Compares the roster at `path` with the expanded instrument (DIS-013).
fn check_roster(out: &mut Outcome, path: &str, instrument: &Value) {
    let Some(_) = read(path, out) else { return };
    let value = match fieldseal_adapters_authoring::decode_path(Path::new(path)) {
        Ok(v) => v,
        Err(e) => {
            out.located_finding("INS-002", "error", path, (e.line, e.column), "", &e.message);
            return;
        }
    };
    match crate::bundle_cmd::parse_roster(value, 1) {
        Ok(roster) => {
            for f in &compare_roster(&roster, instrument) {
                out.finding(path, f);
            }
        }
        Err(message) => out.located_finding("CLI-045", "error", path, (0, 0), "", &message),
    }
}

/// Records resolver problems. `soft` ones are warnings (and errors under `--strict`).
fn resolve_errors(out: &mut Outcome, dir: &str, errors: &[ResolveError], soft: bool) {
    for e in errors {
        let id = match e.kind {
            ResolveKind::Schema(_) => "WIRE-211",
            ResolveKind::Decode(ErrorKind::NotNfc) => "WIRE-004",
            ResolveKind::Decode(_) => "INS-002",
            ResolveKind::Translation(_) => "INS-260",
            _ => "CLI-045",
        };
        let file = if e.file == Path::new(dir).file_name().and_then(|n| n.to_str()).unwrap_or_default() { dir.to_owned() } else { format!("{dir}/{}", e.file) };
        let message = match e.kind {
            ResolveKind::Schema(k) => format!("{}: {}", k.name(), e.message),
            _ => e.message.clone(),
        };
        // A translation finding names its `msgctxt` in the message already.
        let pointer = if matches!(e.kind, ResolveKind::Translation(_)) { "" } else { &e.pointer };
        out.located_finding(id, if soft { "warning" } else { "error" }, &file, (e.line, e.column), pointer, &message);
    }
}

/// The summary line, first.
fn finish(out: &mut Outcome, dir: &str) -> Res {
    let count = |severity: &str| out.findings.iter().filter(|f| f.as_map().and_then(|m| m.get("severity")).and_then(Value::as_text) == Some(severity)).count();
    let (errors, warnings) = (count("error"), count("warning"));
    let line = if errors > 0 {
        msg("survey-invalid", &[("dir", dir), ("errors", &errors.to_string()), ("warnings", &warnings.to_string())])
    } else if warnings > 0 {
        msg("survey-warnings", &[("dir", dir), ("warnings", &warnings.to_string())])
    } else {
        msg("survey-ok", &[("dir", dir)])
    };
    out.lines.insert(0, line);
    Ok(())
}

/// `survey list [--root <dir>]` (CLI-046): name, version, languages and layout windows.
fn list(args: &Args, out: &mut Outcome) -> Res {
    args.optional_file()?;
    let root = args.value("--root").unwrap_or("surveys");
    let tree = match SurveyTree::open(Path::new(root)) {
        Ok(t) => t,
        Err(e) => {
            fail(out, exit::NOT_FOUND, "not-found", &[("file", root), ("reason", &e.message)]);
            return Ok(());
        }
    };
    let mut rows = Vec::new();
    for name in tree.names() {
        let survey = match tree.survey(name) {
            Ok(s) => s,
            Err(e) => {
                out.located_finding("CLI-046", "error", &format!("{root}/{name}"), (0, 0), "", &e.message);
                continue;
            }
        };
        let (version, source) = match std::fs::read(&survey.instrument).ok().and_then(|b| decode_raw(&b, Format::Yaml).ok()) {
            Some(doc) => {
                let version = doc.as_map().and_then(|m| m.get("survey")).and_then(Value::as_map).and_then(|s| s.get("version")).and_then(Value::as_text).unwrap_or("?").to_owned();
                (version, doc.as_map().and_then(|m| m.get("language")).and_then(Value::as_text).unwrap_or("en").to_owned())
            }
            None => ("?".to_owned(), "en".to_owned()),
        };
        let mut languages = vec![source];
        languages.extend(survey.catalogues.iter().map(|c| c.language.clone()));
        let windows: Vec<String> = survey.layouts.iter().map(|l| l.window.clone()).collect();
        rows.push((name.clone(), version, languages, windows));
    }
    let width = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (name, version, languages, windows) in &rows {
        let windows = if windows.is_empty() { "none".to_owned() } else { windows.join(",") };
        out.lines.push(format!("{name:width$}  {version}  languages {}  layouts {windows}", languages.join(",")));
    }
    let text = |s: &String| Value::Text(s.clone());
    out.set(
        "surveys",
        Value::Array(
            rows.iter()
                .map(|(name, version, languages, windows)| {
                    Value::Map(std::collections::BTreeMap::from([
                        ("name".to_owned(), text(name)),
                        ("version".to_owned(), text(version)),
                        ("languages".to_owned(), Value::Array(languages.iter().map(text).collect())),
                        ("windows".to_owned(), Value::Array(windows.iter().map(text).collect())),
                    ]))
                })
                .collect(),
        ),
    );
    Ok(())
}
