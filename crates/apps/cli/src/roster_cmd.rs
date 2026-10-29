//! `fieldseal roster check|diff|list|issue|assign` (CLI §5, CLI-050 to CLI-053, CLI-055).
//!
//! `check`, `diff` and `list` read only their arguments and a copy of the factory's roster store.
//! `issue` and `assign` are operations of the factory (`IssueRoster`, `AssignCohort`): each signs
//! the operator in once through OIDC (`oidc_login`), sends the access token as a Bearer token and
//! writes nothing to disk. No other command in the CLI signs anyone in (REG-001).
//!
//! No command prints a subject id or a roster value unless `diff` is given `--reveal` (CLI-008).
//! `assign --list` prints the accounts the factory journaled: the operator's own audit trail.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fieldseal_adapters_authoring::decode_path;
use fieldseal_adapters_authoring::survey::SurveyTree;
use fieldseal_adapters_file::roster_store::RosterStore;
use fieldseal_distribution::domain::{ConsentState, Roster, RosterEntry, check_issue_form};
use fieldseal_instrument::domain::Severity;
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::CohortId;

use crate::args::Args;
use crate::bundle_cmd::parse_roster;
use crate::clients::{ClientError, connect_operator, report};
use crate::oidc_login::{self, SignInError};
use crate::json;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::roster_check::{check_roster_form, compare_roster};
use crate::support::{Res, fail, parse_uint, read, run_command, setting, usage};

/// Runs `roster <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    Some(match verb {
        "check" => run_command("roster check", raw, &["--instrument"], &[], check),
        "diff" => run_command("roster diff", raw, &["--store"], &["--reveal"], diff),
        "list" => run_command("roster list", raw, &["--store", "--cohort"], &[], list),
        "issue" => run_command("roster issue", raw, &["--factory-url", "--instrument", "--login", "--browser", "--issuer", "--client-id"], &[], issue),
        "assign" => run_command(
            "roster assign",
            raw,
            &["--factory-url", "--account", "--assign", "--login", "--browser", "--issuer", "--client-id", "--remove", "--unassign"],
            &["--list"],
            assign,
        ),
        _ => return None,
    })
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn int(n: usize) -> Value {
    Value::Int(n as i128)
}

/// The expanded instrument of each survey folder. A survey folder is the only instrument source:
/// resolving an address needs a registry. `None` when one does not load (the error is recorded).
fn load_instruments(dirs: &[String], out: &mut Outcome) -> Res<Option<Vec<Value>>> {
    let mut instruments = Vec::new();
    for dir in dirs {
        let dir = dir.trim_end_matches('/');
        let canonical = std::fs::canonicalize(dir).map_err(|_| usage("not-a-survey-folder", &[("file", dir)]))?;
        let (Some(root), Some(name)) = (canonical.parent(), canonical.file_name().and_then(|n| n.to_str())) else {
            return Err(usage("not-a-survey-folder", &[("file", dir)]));
        };
        let survey = SurveyTree::open(root).and_then(|tree| tree.survey(name)).map_err(|_| usage("not-a-survey-folder", &[("file", dir)]))?;
        match survey.load() {
            Ok(loaded) => instruments.push(loaded.instrument),
            Err(_) => {
                fail(out, exit::FAILED, "roster-survey-invalid", &[("dir", dir)]);
                return Ok(None);
            }
        }
    }
    Ok(Some(instruments))
}

// ---- check ------------------------------------------------------------------------------------

/// `roster check <file> --instrument <survey dir>...`: the closed-schema check (DIS-063), then the
/// comparison with every instrument (DIS-013). Writes nothing (CLI-050).
fn check(args: &Args, out: &mut Outcome) -> Res {
    let path = args.file("roster check")?;
    let dirs = args.values("--instrument");
    if dirs.is_empty() {
        return Err(usage("missing-flag", &[("command", "roster check"), ("flag", "--instrument")]));
    }
    let Some(instruments) = load_instruments(dirs, out)? else { return Ok(()) };
    let Some(_) = read(path, out) else { return Ok(()) };
    let value = match decode_path(Path::new(path)) {
        Ok(v) => v,
        Err(e) => {
            out.located_finding("INS-002", "error", path, (e.line, e.column), "", &e.message);
            return Ok(());
        }
    };
    let roster = match check_roster_form(value) {
        Ok(r) => r,
        Err(findings) => {
            for f in findings {
                out.raw_finding("DIS-063", "error", path, &f.path, &f.message);
            }
            return Ok(());
        }
    };
    // An error counts against any instrument; a note only when no instrument reads the field.
    let per_instrument: Vec<_> = instruments.iter().map(|i| compare_roster(&roster, i)).collect();
    for f in per_instrument.iter().flatten().filter(|f| f.severity == Severity::Error) {
        out.finding(path, f);
    }
    if let Some(first) = per_instrument.first() {
        for f in first.iter().filter(|f| f.severity != Severity::Error) {
            if per_instrument.iter().all(|all| all.iter().any(|g| g.message == f.message)) {
                out.finding(path, f);
            }
        }
    }
    let counts = consent_counts(&roster);
    out.lines.insert(0, summary(&format!("{}@{}", roster.cohort.as_str(), roster.version), roster.entries.len(), &counts));
    out.set("cohort", text(roster.cohort.as_str()));
    out.set("version", Value::Int(i128::from(roster.version)));
    out.set("subjects", int(roster.entries.len()));
    out.set("consent", consent_value(&counts));
    Ok(())
}

// ---- diff -------------------------------------------------------------------------------------

/// One side of a diff: the roster and the name the operator gave it.
struct Operand {
    label: String,
    roster: Roster,
}

/// A roster from a file, or `<cohort>@<version>` from the store (a file of that name wins).
fn operand(arg: &str, store: Option<&str>, out: &mut Outcome) -> Res<Option<Operand>> {
    let stored = arg.rsplit_once('@').filter(|_| !Path::new(arg).is_file());
    let Some((cohort, version)) = stored else {
        let Some(_) = read(arg, out) else { return Ok(None) };
        let value = match decode_path(Path::new(arg)) {
            Ok(v) => v,
            Err(e) => {
                out.located_finding("INS-002", "error", arg, (e.line, e.column), "", &e.message);
                return Ok(None);
            }
        };
        return match parse_roster(value, 1) {
            Ok(roster) => Ok(Some(Operand { label: arg.to_owned(), roster })),
            Err(message) => {
                out.located_finding("CLI-050", "error", arg, (0, 0), "", &message);
                Ok(None)
            }
        };
    };
    let Some(dir) = store else { return Err(usage("roster-store-needed", &[("operand", arg)])) };
    let (Ok(cohort), Some(version)) = (CohortId::new(cohort), parse_uint(version)) else {
        fail(out, exit::NOT_FOUND, "roster-no-version", &[("operand", arg)]);
        return Ok(None);
    };
    let Some(store) = open_store(dir, out) else { return Ok(None) };
    match store.get(&cohort, version) {
        Ok(Some(roster)) => Ok(Some(Operand { label: arg.to_owned(), roster })),
        Ok(None) => {
            fail(out, exit::NOT_FOUND, "roster-no-version", &[("operand", arg)]);
            Ok(None)
        }
        Err(e) => {
            fail(out, exit::CONFIG, "roster-store-failed", &[("dir", dir), ("reason", &e.to_string())]);
            Ok(None)
        }
    }
}

/// Opens a store that already exists; the command never creates one.
fn open_store(dir: &str, out: &mut Outcome) -> Option<RosterStore> {
    if !Path::new(dir).is_dir() {
        fail(out, exit::NOT_FOUND, "roster-store-missing", &[("dir", dir)]);
        return None;
    }
    match RosterStore::open(dir) {
        Ok(s) => Some(s),
        Err(e) => {
            fail(out, exit::CONFIG, "roster-store-failed", &[("dir", dir), ("reason", &e.to_string())]);
            None
        }
    }
}

/// `roster diff <a> <b> [--store <dir>] [--reveal]`: counts of added, removed and kept subjects,
/// consent and `prior_status` changes and the names of the fields that changed. Ids and values
/// only with `--reveal` (CLI-052, DIS-081).
fn diff(args: &Args, out: &mut Outcome) -> Res {
    let (a, b) = match args.positionals.as_slice() {
        [a, b] => (a.as_str(), b.as_str()),
        [] | [_] => return Err(usage("missing-file", &[("command", "roster diff")])),
        [_, _, extra, ..] => return Err(usage("extra-argument", &[("argument", extra)])),
    };
    let store = args.value("--store");
    let reveal = args.has("--reveal");
    let Some(a) = operand(a, store, out)? else { return Ok(()) };
    let Some(b) = operand(b, store, out)? else { return Ok(()) };
    if a.roster.cohort != b.roster.cohort {
        return Err(usage("roster-different-cohort", &[("a", &a.label), ("b", &b.label)]));
    }
    if reveal {
        eprintln!("{}", msg("roster-reveal-warning", &[]));
    }
    let before: BTreeMap<&str, &RosterEntry> = a.roster.entries.iter().map(|e| (e.subject.as_str(), e)).collect();
    let after: BTreeMap<&str, &RosterEntry> = b.roster.entries.iter().map(|e| (e.subject.as_str(), e)).collect();
    let added: Vec<&RosterEntry> = after.iter().filter(|(id, _)| !before.contains_key(*id)).map(|(_, e)| *e).collect();
    let removed: Vec<&RosterEntry> = before.iter().filter(|(id, _)| !after.contains_key(*id)).map(|(_, e)| *e).collect();
    let kept: Vec<(&RosterEntry, &RosterEntry)> = before.iter().filter_map(|(id, old)| after.get(id).map(|new| (*old, *new))).collect();

    let mut consent: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let mut prior = 0;
    let mut fields = BTreeSet::new();
    for (old, new) in &kept {
        if old.consent != new.consent {
            *consent.entry((old.consent.as_str(), new.consent.as_str())).or_default() += 1;
        }
        if old.prior_status != new.prior_status {
            prior += 1;
        }
        fields.extend(changed_fields(old, new).into_keys());
    }

    out.lines.push(format!("{} -> {}", a.label, b.label));
    if b.roster.version < a.roster.version {
        out.lines.push(format!("note: {} is an older version than {}", b.label, a.label));
    } else if let Err(e) = a.roster.may_be_followed_by(&b.roster) {
        out.lines.push(format!("note: {e}"));
    }
    out.lines.push(format!("subjects added: {}", added.len()));
    out.lines.push(format!("subjects removed: {}", removed.len()));
    out.lines.push(format!("subjects kept: {}", kept.len()));
    if consent.is_empty() {
        out.lines.push("consent changes: none".to_owned());
    }
    for ((from, to), n) in &consent {
        out.lines.push(format!("consent changes: {from} -> {to}: {n}"));
    }
    out.lines.push(format!("prior_status changes: {prior}"));
    out.lines.push(format!("changed fields: {}", if fields.is_empty() { "none".to_owned() } else { fields.iter().cloned().collect::<Vec<_>>().join(", ") }));

    out.set("from", text(&a.label));
    out.set("to", text(&b.label));
    out.set("added", int(added.len()));
    out.set("removed", int(removed.len()));
    out.set("kept", int(kept.len()));
    out.set(
        "consentChanges",
        Value::Array(
            consent
                .iter()
                .map(|((from, to), n)| fieldseal_kernel::cbor::map([("from", text(from)), ("to", text(to)), ("count", int(*n))]))
                .collect(),
        ),
    );
    out.set("priorStatusChanges", int(prior));
    out.set("changedFields", Value::Array(fields.iter().map(|f| text(f)).collect()));

    if reveal {
        let mut detail = Vec::new();
        for e in &added {
            out.lines.push(format!("added: {} ({})", e.subject.as_str(), e.display));
            detail.push(fieldseal_kernel::cbor::map([("change", text("added")), ("subject", text(e.subject.as_str()))]));
        }
        for e in &removed {
            out.lines.push(format!("removed: {} ({})", e.subject.as_str(), e.display));
            detail.push(fieldseal_kernel::cbor::map([("change", text("removed")), ("subject", text(e.subject.as_str()))]));
        }
        for (old, new) in &kept {
            let id = old.subject.as_str();
            if old.consent != new.consent {
                out.lines.push(format!("consent {id}: {} -> {}", old.consent.as_str(), new.consent.as_str()));
                detail.push(fieldseal_kernel::cbor::map([("change", text("consent")), ("subject", text(id)), ("from", text(old.consent.as_str())), ("to", text(new.consent.as_str()))]));
            }
            if old.prior_status != new.prior_status {
                let show = |p: &Option<String>| p.clone().unwrap_or_else(|| "none".to_owned());
                out.lines.push(format!("prior_status {id}: {} -> {}", show(&old.prior_status), show(&new.prior_status)));
                detail.push(fieldseal_kernel::cbor::map([("change", text("prior_status")), ("subject", text(id)), ("from", text(&show(&old.prior_status))), ("to", text(&show(&new.prior_status)))]));
            }
            for (name, (from, to)) in changed_fields(old, new) {
                let show = |v: &Option<&Value>| v.map_or_else(|| "none".to_owned(), json::compact);
                out.lines.push(format!("field {id}.{name}: {} -> {}", show(&from), show(&to)));
                detail.push(fieldseal_kernel::cbor::map([("change", text("field")), ("subject", text(id)), ("field", text(&name)), ("from", text(&show(&from))), ("to", text(&show(&to)))]));
            }
        }
        out.set("revealed", Value::Array(detail));
    }
    Ok(())
}

/// The fields whose value differs between a subject's two versions, with both values.
fn changed_fields<'a>(old: &'a RosterEntry, new: &'a RosterEntry) -> BTreeMap<String, (Option<&'a Value>, Option<&'a Value>)> {
    old.attributes
        .keys()
        .chain(new.attributes.keys())
        .filter(|k| old.attributes.get(*k) != new.attributes.get(*k))
        .map(|k| (k.clone(), (old.attributes.get(k), new.attributes.get(k))))
        .collect()
}

// ---- list -------------------------------------------------------------------------------------

/// `roster list --store <dir> [--cohort <id>]`: each stored version as `<cohort>@<version>` with
/// its digest and counts, and no ids (CLI-053).
fn list(args: &Args, out: &mut Outcome) -> Res {
    if let Some(extra) = args.positionals.first() {
        return Err(usage("extra-argument", &[("argument", extra)]));
    }
    let dir = args.required("roster list", "--store")?;
    let Some(store) = open_store(dir, out) else { return Ok(()) };
    let fail_store = |out: &mut Outcome, e: &dyn std::fmt::Display| fail(out, exit::CONFIG, "roster-store-failed", &[("dir", dir), ("reason", &e.to_string())]);
    let cohorts = match args.value("--cohort") {
        Some(c) => match CohortId::new(c) {
            Ok(c) => vec![c],
            Err(_) => return Err(usage("roster-no-cohort", &[("cohort", c)])),
        },
        None => match store.cohorts() {
            Ok(c) => c,
            Err(e) => {
                fail_store(out, &e);
                return Ok(());
            }
        },
    };
    let mut rows = Vec::new();
    for cohort in &cohorts {
        let versions = match store.versions(cohort) {
            Ok(v) => v,
            Err(e) => {
                fail_store(out, &e);
                return Ok(());
            }
        };
        if versions.is_empty() && args.value("--cohort").is_some() {
            fail(out, exit::NOT_FOUND, "roster-no-cohort", &[("cohort", cohort.as_str())]);
            return Ok(());
        }
        for version in versions {
            let roster = match store.get(cohort, version) {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) => {
                    fail_store(out, &e);
                    return Ok(());
                }
            };
            let name = format!("{}@{version}", cohort.as_str());
            let digest = lower_hex(sha256(&roster.encode()).as_bytes());
            let counts = consent_counts(&roster);
            out.lines.push(format!("{name}  sha256:{digest}  {}", summary_counts(roster.entries.len(), &counts)));
            rows.push(fieldseal_kernel::cbor::map([
                ("name", text(&name)),
                ("cohort", text(cohort.as_str())),
                ("version", Value::Int(i128::from(version))),
                ("digest", text(&format!("sha256:{digest}"))),
                ("subjects", int(roster.entries.len())),
                ("consent", consent_value(&counts)),
            ]));
        }
    }
    out.set("rosters", Value::Array(rows));
    Ok(())
}

// ---- issue ------------------------------------------------------------------------------------

/// Records why a sign-in did not give a token, with the exit code of its kind.
fn sign_in_failed(out: &mut Outcome, e: &SignInError) {
    match e {
        SignInError::NeedsPerson => fail(out, exit::FAILED, "sign-in-needs-person", &[]),
        SignInError::Refused(reason) => fail(out, exit::FAILED, "sign-in-failed", &[("reason", reason)]),
        SignInError::Unavailable(reason) => fail(out, exit::CONFIG, "sign-in-unreachable", &[("reason", reason)]),
        SignInError::TimedOut => fail(out, exit::FAILED, "sign-in-timeout", &[("seconds", "180")]),
    }
}

/// `roster issue <file>... --factory-url <url> [--instrument <survey dir>...]`: runs the check
/// on every file first and sends nothing if any fails; then one sign-in and one `POST /v1/rosters`
/// per file. Prints each stored version and digest, or `unchanged` (CLI-051).
fn issue(args: &Args, out: &mut Outcome) -> Res {
    if args.positionals.is_empty() {
        return Err(usage("missing-file", &[("command", "roster issue")]));
    }
    let settings = oidc_login::settings(args, "roster issue")?;
    let Some(url) = setting(args, "--factory-url", "FIELDSEAL_FACTORY_URL") else {
        fail(out, exit::CONFIG, "no-factory-url", &[]);
        return Ok(());
    };
    let Some(instruments) = load_instruments(args.values("--instrument"), out)? else { return Ok(()) };
    // The same check as `roster check`, on every file, before anyone is signed in.
    let mut bodies = Vec::new();
    for path in &args.positionals {
        let Some(_) = read(path, out) else { return Ok(()) };
        let value = match decode_path(Path::new(path)) {
            Ok(v) => v,
            Err(e) => {
                out.located_finding("INS-002", "error", path, (e.line, e.column), "", &e.message);
                continue;
            }
        };
        let form = match check_issue_form(value) {
            Ok(form) => form,
            Err(findings) => {
                for f in findings {
                    out.raw_finding("DIS-063", "error", path, &f.path, &f.message);
                }
                continue;
            }
        };
        let roster = form.clone().into_roster(fieldseal_kernel::id::Generation(1));
        for instrument in &instruments {
            for f in compare_roster(&roster, instrument).iter().filter(|f| f.severity == Severity::Error) {
                out.finding(path, f);
            }
        }
        bodies.push((path.as_str(), form));
    }
    if out.exit != exit::OK {
        return Ok(());
    }
    let client = match connect_operator(&url) {
        Ok(c) => c,
        Err(e) => {
            report(out, &url, &e);
            return Ok(());
        }
    };
    let token = match oidc_login::sign_in(&settings) {
        Ok(t) => t,
        Err(e) => {
            sign_in_failed(out, &e);
            return Ok(());
        }
    };
    let mut rows = Vec::new();
    for (path, form) in &bodies {
        match client.issue_roster(&token, &form.encode()) {
            Ok(done) => {
                let name = format!("{}@{}", form.cohort.as_str(), done.version);
                out.lines.push(msg("roster-issue-line", &[("name", &name), ("digest", &done.digest), ("status", if done.status == "issued" { "stored" } else { &done.status })]));
                rows.push(fieldseal_kernel::cbor::map([
                    ("name", text(&name)),
                    ("cohort", text(form.cohort.as_str())),
                    ("version", Value::Int(i128::from(done.version))),
                    ("digest", text(&done.digest)),
                    ("status", text(&done.status)),
                ]));
            }
            Err(ClientError::Refused { code, .. }) if code == "not-newer" || code == "version-taken" => {
                let id = if code == "not-newer" { "roster-issue-not-newer" } else { "roster-issue-version-taken" };
                fail(out, exit::FAILED, id, &[("file", path), ("cohort", form.cohort.as_str())]);
            }
            Err(e) => report(out, &url, &e),
        }
    }
    out.set("rosters", Value::Array(rows));
    Ok(())
}

// ---- assign -----------------------------------------------------------------------------------

/// `roster assign --factory-url <url> --account <oidc-subject> (--assign <survey>=<cohort>)...`:
/// one sign-in, one `POST /v1/assignments` per `--assign`. `--list` prints the journal. The
/// command removes nothing, and a request to remove names REG-045 (CLI-055).
fn assign(args: &Args, out: &mut Outcome) -> Res {
    if let Some(extra) = args.positionals.first() {
        return Err(usage("extra-argument", &[("argument", extra)]));
    }
    for flag in ["--remove", "--unassign"] {
        if args.value(flag).is_some() {
            return Err(usage("roster-assign-no-remove", &[("flag", flag)]));
        }
    }
    let list = args.has("--list");
    let mut pairs = Vec::new();
    for pair in args.values("--assign") {
        match pair.split_once('=').filter(|(s, c)| !s.is_empty() && !c.is_empty()) {
            Some((survey, cohort)) => pairs.push((survey, cohort)),
            None => return Err(usage("roster-assign-bad-pair", &[("pair", pair)])),
        }
    }
    let account = args.value("--account").filter(|a| !a.is_empty());
    if !list && (account.is_none() || pairs.is_empty()) || list && (account.is_some() || !pairs.is_empty()) {
        return Err(usage("roster-assign-needs", &[]));
    }
    let settings = oidc_login::settings(args, "roster assign")?;
    let Some(url) = setting(args, "--factory-url", "FIELDSEAL_FACTORY_URL") else {
        fail(out, exit::CONFIG, "no-factory-url", &[]);
        return Ok(());
    };
    let client = match connect_operator(&url) {
        Ok(c) => c,
        Err(e) => {
            report(out, &url, &e);
            return Ok(());
        }
    };
    let token = match oidc_login::sign_in(&settings) {
        Ok(t) => t,
        Err(e) => {
            sign_in_failed(out, &e);
            return Ok(());
        }
    };
    if list {
        let rows = match client.assignments(&token) {
            Ok(rows) => rows,
            Err(e) => {
                report(out, &url, &e);
                return Ok(());
            }
        };
        if rows.is_empty() {
            out.lines.push(msg("roster-assign-none", &[]));
        }
        for r in &rows {
            out.lines.push(format!("#{} {}  account {}: {} -> cohort {} (generation {})  by {}", r.seq, r.at, r.account, r.survey, r.cohort, r.generation, r.by));
        }
        out.set(
            "assignments",
            Value::Array(
                rows.iter()
                    .map(|r| {
                        fieldseal_kernel::cbor::map([
                            ("seq", Value::Int(i128::from(r.seq))),
                            ("account", text(&r.account)),
                            ("survey", text(&r.survey)),
                            ("cohort", text(&r.cohort)),
                            ("generation", Value::Int(i128::from(r.generation))),
                            ("by", text(&r.by)),
                            ("at", text(&r.at)),
                        ])
                    })
                    .collect(),
            ),
        );
        return Ok(());
    }
    let account = account.unwrap_or_default();
    let mut done = Vec::new();
    for (survey, cohort) in pairs {
        match client.assign(&token, account, survey, cohort) {
            Ok(answer) => {
                out.lines.push(msg(
                    "roster-assign-line",
                    &[("account", account), ("survey", survey), ("cohort", cohort), ("generation", &answer.generation.to_string()), ("status", &answer.status)],
                ));
                done.push(fieldseal_kernel::cbor::map([
                    ("account", text(account)),
                    ("survey", text(survey)),
                    ("cohort", text(cohort)),
                    ("generation", Value::Int(i128::from(answer.generation))),
                    ("status", text(&answer.status)),
                ]));
            }
            Err(e) => report(out, &url, &e),
        }
    }
    out.set("assignments", Value::Array(done));
    Ok(())
}

// ---- counts -----------------------------------------------------------------------------------

fn consent_counts(roster: &Roster) -> [(ConsentState, usize); 3] {
    [ConsentState::Granted, ConsentState::Refused, ConsentState::Unknown].map(|c| (c, roster.entries.iter().filter(|e| e.consent == c).count()))
}

fn consent_value(counts: &[(ConsentState, usize); 3]) -> Value {
    Value::Map(counts.iter().map(|(c, n)| (c.as_str().to_owned(), int(*n))).collect())
}

fn summary_counts(subjects: usize, counts: &[(ConsentState, usize); 3]) -> String {
    let consent: Vec<String> = counts.iter().map(|(c, n)| format!("{} {n}", c.as_str())).collect();
    format!("{subjects} subjects ({})", consent.join(", "))
}

fn summary(name: &str, subjects: usize, counts: &[(ConsentState, usize); 3]) -> String {
    format!("{name}: {}", summary_counts(subjects, counts))
}
