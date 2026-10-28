//! The pieces a conformance suite is built from: results, a collector and small helpers
//! that fail with a message instead of panicking.

use std::fmt::Debug;

/// How one check ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// The check passed.
    Pass,
    /// The check failed, with the reason.
    Fail(String),
}

/// The result of one check: what it verified, and whether it held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    /// The unit that produced it (for example `wire:cbor` or `contract:PolicyEngine:BuiltInPolicyEngine`).
    pub unit: String,
    /// A name for the check within its unit.
    pub name: String,
    /// The requirement IDs the check verifies; may be empty for an unnumbered contract.
    pub requirements: Vec<String>,
    /// How it ended.
    pub status: Status,
}

/// Collects results while a unit runs.
pub struct Collector {
    unit: String,
    /// The results so far.
    pub results: Vec<CheckResult>,
}

impl Collector {
    /// A collector for `unit`.
    pub fn new(unit: &str) -> Self {
        Self { unit: unit.to_owned(), results: Vec::new() }
    }

    /// Runs one check naming `requirements` and records its result.
    pub fn case(&mut self, requirements: &[String], name: impl Into<String>, f: impl FnOnce() -> Result<(), String>) {
        let status = match f() {
            Ok(()) => Status::Pass,
            Err(m) => Status::Fail(m),
        };
        self.results.push(CheckResult { unit: self.unit.clone(), name: name.into(), requirements: requirements.to_vec(), status });
    }
}

/// One named check of a table-driven unit: the requirement IDs it verifies, a name, and a
/// function that panics (with assertions) when the check fails.
#[derive(Clone, Copy)]
pub struct Check {
    /// The requirement IDs the check exercises.
    pub reqs: &'static [&'static str],
    /// The check's name.
    pub name: &'static str,
    /// The check; a panic is a failure.
    pub run: fn(),
}

impl Collector {
    /// Runs a panicking check and records its result. In a build that aborts on panic the
    /// whole unit crashes instead, which the parent reports against every requirement the
    /// unit claims.
    pub fn check(&mut self, check: &Check) {
        let reqs: Vec<String> = check.reqs.iter().map(|r| (*r).to_owned()).collect();
        let run = check.run;
        let outcome = std::panic::catch_unwind(run);
        let status = match outcome {
            Ok(()) => Status::Pass,
            Err(p) => Status::Fail(
                p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned())).unwrap_or_else(|| "an assertion failed".into()),
            ),
        };
        self.results.push(CheckResult { unit: self.unit.clone(), name: check.name.to_owned(), requirements: reqs, status });
    }
}

/// Turns a `Result` with a debuggable error, or an `Option`, into a `Result<_, String>`.
pub trait Chk<T> {
    /// Converts, keeping the error's debug form.
    fn c(self) -> Result<T, String>;
}

impl<T, E: Debug> Chk<T> for Result<T, E> {
    fn c(self) -> Result<T, String> {
        self.map_err(|e| format!("{e:?}"))
    }
}

impl<T> Chk<T> for Option<T> {
    fn c(self) -> Result<T, String> {
        self.ok_or_else(|| "a value was missing".to_owned())
    }
}

/// Fails the check unless the condition holds.
macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err(format!($($arg)+));
        }
    };
}

/// Fails the check unless the two sides are equal.
macro_rules! same {
    ($left:expr, $right:expr, $($arg:tt)+) => {{
        let (l, r) = (&$left, &$right);
        if l != r {
            return Err(format!("{}: {:?} != {:?}", format!($($arg)+), l, r));
        }
    }};
}

pub(crate) use {ensure, same};

/// Decodes lower-case hex.
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    crate::support::unhex(s).ok_or_else(|| format!("not hexadecimal: {s}"))
}

/// The requirement IDs a vector's `requirement` field names (`WIRE-001`, lists such as
/// `WIRE-141, WIRE-144`, and ranges such as `WIRE-130..135`), or `fallback` when it names none.
pub fn requirement_ids(field: Option<&serde_json::Value>, fallback: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(text) = field.and_then(|v| v.as_str()) {
        let mut last: Option<(String, u32)>;
        let mut rest = text;
        while let Some(pos) = rest.find(|c: char| c.is_ascii_uppercase()) {
            rest = &rest[pos..];
            let Some((prefix, tail)) = rest.split_once('-') else { break };
            if prefix.len() < 2 || prefix.len() > 5 || !prefix.chars().all(|c| c.is_ascii_uppercase()) {
                rest = &rest[1..];
                continue;
            }
            let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
            let Ok(n) = digits.parse::<u32>() else {
                rest = &rest[1..];
                continue;
            };
            // `WIRE-130..135`: a bare number after `..` ends a range.
            let after = &tail[digits.len()..];
            out.push(format!("{prefix}-{n:03}"));
            last = Some((prefix.to_owned(), n));
            rest = after;
            if let Some(range_end) = after.strip_prefix("..") {
                let end_text: String = range_end.chars().take_while(char::is_ascii_digit).collect();
                if let (Ok(end), Some((p, start))) = (end_text.parse::<u32>(), last.clone()) {
                    for k in start + 1..=end {
                        out.push(format!("{p}-{k:03}"));
                    }
                    rest = &range_end[end_text.len()..];
                }
            }
        }
    }
    if out.is_empty() {
        out = fallback.iter().map(|s| (*s).to_owned()).collect();
    }
    out
}

/// A case's label: its `id` or `name` field, else its position.
pub fn label(case: &serde_json::Value, index: usize) -> String {
    case.get("id").or_else(|| case.get("name")).and_then(|v| v.as_str()).map_or_else(|| format!("#{index}"), str::to_owned)
}
