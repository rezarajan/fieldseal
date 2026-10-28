//! A command's outcome (CLI §6): exit code, human output and the `--json` document.

use std::collections::BTreeMap;
use std::io::Write as _;

use fieldseal_instrument::domain::{Finding, FindingKind, Severity};
use fieldseal_kernel::Value;

use crate::json;

/// Exit codes (CLI-005).
pub mod exit {
    /// Success.
    pub const OK: u8 = 0;
    /// Verification or validation failed.
    pub const FAILED: u8 = 1;
    /// Usage error.
    pub const USAGE: u8 = 2;
    /// Configuration or adapter error.
    pub const CONFIG: u8 = 3;
    /// A resource was not found.
    pub const NOT_FOUND: u8 = 4;
    /// A policy denied the operation.
    pub const DENIED: u8 = 5;
    /// Internal error.
    pub const INTERNAL: u8 = 6;
}

/// What a command produced.
#[derive(Debug)]
pub struct Outcome {
    /// `<noun> <verb>`.
    pub command: &'static str,
    /// The exit code; the highest-priority failure wins (see [`Outcome::fail`]).
    pub exit: u8,
    /// Findings, as `--json` objects.
    pub findings: Vec<Value>,
    /// Human lines for stdout (from the message catalogue, or findings).
    pub lines: Vec<String>,
    /// Human output printed after the lines (a page, a JSON tree), unless `--json`.
    pub body: Option<String>,
    /// Further fields of the `--json` document.
    pub extra: BTreeMap<String, Value>,
    /// A message for stderr (usage and resource errors), not part of stdout.
    pub error: Option<String>,
}

impl Outcome {
    /// A successful outcome so far.
    pub fn new(command: &'static str) -> Self {
        Self { command, exit: exit::OK, findings: Vec::new(), lines: Vec::new(), body: None, extra: BTreeMap::new(), error: None }
    }

    /// Records a failure. Validation failures (1) don't hide usage (2), configuration (3),
    /// not-found (4) or internal (6) errors.
    pub fn fail(&mut self, code: u8) {
        if self.exit == exit::OK || (self.exit == exit::FAILED && code != exit::OK) {
            self.exit = code;
        }
    }

    /// A usage or resource error with its message for stderr.
    pub fn error(&mut self, code: u8, message: String) {
        self.fail(code);
        if self.error.is_none() {
            self.error = Some(message);
        }
    }

    /// Adds an instrument or layout finding from `file`; an error fails the outcome.
    pub fn finding(&mut self, file: &str, f: &Finding) {
        if f.severity == Severity::Error {
            self.fail(exit::FAILED);
        }
        self.lines.push(format!("{file}: {f}"));
        self.findings.push(finding_value(f.requirement, severity_name(f.severity), Some(kind_name(f.kind)), &f.message, file, &f.path));
    }

    /// Adds a finding given by parts (decoding errors, policy findings).
    pub fn raw_finding(&mut self, id: &str, severity: &str, file: &str, path: &str, message: &str) {
        if severity == "error" {
            self.fail(exit::FAILED);
        }
        let at = if path.is_empty() { String::new() } else { format!(" at {path}") };
        self.lines.push(format!("{file}: {severity} {id}{at}: {message}"));
        self.findings.push(finding_value(id, severity, None, message, file, path));
    }

    /// Sets a `--json` field.
    pub fn set(&mut self, key: &str, v: Value) {
        self.extra.insert(key.to_owned(), v);
    }

    /// Writes the outcome to stdout (and its error to stderr) and returns the exit code.
    pub fn emit(self, as_json: bool) -> u8 {
        if let Some(e) = &self.error {
            eprintln!("{e}");
        }
        let mut stdout = std::io::stdout().lock();
        if as_json {
            let mut doc = self.extra;
            doc.insert("command".into(), Value::Text(self.command.into()));
            doc.insert("ok".into(), Value::Bool(self.exit == exit::OK));
            doc.insert("exitCode".into(), Value::Int(i128::from(self.exit)));
            doc.insert("findings".into(), Value::Array(self.findings));
            let _ = writeln!(stdout, "{}", json::compact(&Value::Map(doc)));
        } else {
            for l in &self.lines {
                let _ = writeln!(stdout, "{l}");
            }
            if let Some(b) = &self.body {
                let _ = stdout.write_all(b.as_bytes());
                if !b.ends_with('\n') {
                    let _ = writeln!(stdout);
                }
            }
        }
        let _ = stdout.flush();
        self.exit
    }
}

fn finding_value(id: &str, severity: &str, kind: Option<&str>, message: &str, file: &str, path: &str) -> Value {
    let mut m = BTreeMap::new();
    m.insert("id".to_owned(), Value::Text(id.to_owned()));
    m.insert("severity".to_owned(), Value::Text(severity.to_owned()));
    if let Some(k) = kind {
        m.insert("kind".to_owned(), Value::Text(k.to_owned()));
    }
    m.insert("message".to_owned(), Value::Text(message.to_owned()));
    let mut w = BTreeMap::new();
    w.insert("file".to_owned(), Value::Text(file.to_owned()));
    if !path.is_empty() {
        w.insert("path".to_owned(), Value::Text(path.to_owned()));
    }
    m.insert("where".to_owned(), Value::Map(w));
    Value::Map(m)
}

/// `error`, `warning` or `advice`.
pub fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advice => "advice",
    }
}

/// The error class, as `ValidateInstrument` and `ValidateLayout` name it (INS §3).
pub fn kind_name(k: FindingKind) -> &'static str {
    match k {
        FindingKind::SchemaViolation => "SchemaViolation",
        FindingKind::UnknownControl => "UnknownControl",
        FindingKind::UnknownItemPath => "UnknownItemPath",
        FindingKind::UnboundedRule => "UnboundedRule",
        FindingKind::IncompatibleSchemaRange => "IncompatibleSchemaRange",
        FindingKind::FingerprintMismatch => "FingerprintMismatch",
        FindingKind::UnplacedQuestion => "UnplacedQuestion",
        FindingKind::DuplicatePlacement => "DuplicatePlacement",
        FindingKind::OrderChanged => "OrderChanged",
        FindingKind::ContentOverride => "ContentOverride",
        FindingKind::UnsupportedPresentation => "UnsupportedPresentation",
        FindingKind::Lint => "Lint",
    }
}
