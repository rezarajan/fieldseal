//! Command-line arguments: positionals, `--flag value` (or `--flag=value`) and switches.

use std::collections::BTreeMap;

use crate::messages::msg;

/// The parsed arguments of one command.
#[derive(Debug, Default)]
pub struct Args {
    /// Arguments that are not flags, in order.
    pub positionals: Vec<String>,
    /// Flags with values, each value in order.
    pub flags: BTreeMap<String, Vec<String>>,
    /// Switches present.
    pub switches: Vec<String>,
}

/// The flags that may be given more than once; every other flag may be given at most once
/// (CLI-022), so a repeated `--out` is refused instead of the last one silently winning.
pub const REPEATABLE: &[&str] = &[
    "--lang", "--layout", "--reviewers", "--revocations", "--key", "--policy", "--build", "--instrument", "--log-origin", "--log", "--roster", "--assign",
];

/// Why the arguments were refused: a usage error (exit 2).
#[derive(Debug)]
pub struct UsageError(pub String);

impl Args {
    /// Parses `raw` for `command`, which takes the flags `valued` (with a value) and
    /// `switches` (without). `--json` and `--help` are always accepted.
    pub fn parse(command: &str, raw: &[String], valued: &[&str], switches: &[&str]) -> Result<Self, UsageError> {
        let mut a = Args::default();
        let mut i = 0;
        while i < raw.len() {
            let arg = &raw[i];
            i += 1;
            if arg == "--" {
                a.positionals.extend(raw[i..].iter().cloned());
                break;
            }
            if !arg.starts_with('-') || arg == "-" {
                a.positionals.push(arg.clone());
                continue;
            }
            let (name, inline) = match arg.split_once('=') {
                Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
                None => (arg.clone(), None),
            };
            if valued.contains(&name.as_str()) {
                let value = match inline {
                    Some(v) => v,
                    None => {
                        let v = raw.get(i).ok_or_else(|| UsageError(msg("missing-value", &[("flag", &name)])))?;
                        if v.starts_with("--") {
                            return Err(UsageError(msg("flag-as-value", &[("flag", &name), ("value", v)])));
                        }
                        i += 1;
                        v.clone()
                    }
                };
                if a.flags.contains_key(&name) && !REPEATABLE.contains(&name.as_str()) {
                    return Err(UsageError(msg("duplicate-flag", &[("flag", &name)])));
                }
                a.flags.entry(name).or_default().push(value);
            } else if (switches.contains(&name.as_str()) || name == "--json" || name == "--help") && inline.is_none() {
                a.switches.push(name);
            } else {
                return Err(UsageError(msg("unknown-flag", &[("command", command), ("flag", &name)])));
            }
        }
        Ok(a)
    }

    /// Whether the switch is present.
    pub fn has(&self, switch: &str) -> bool {
        self.switches.iter().any(|s| s == switch)
    }

    /// The last value of a flag.
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.flags.get(flag).and_then(|v| v.last()).map(String::as_str)
    }

    /// Every value of a flag, in order.
    pub fn values(&self, flag: &str) -> &[String] {
        self.flags.get(flag).map_or(&[], Vec::as_slice)
    }

    /// The one positional file argument.
    pub fn file(&self, command: &str) -> Result<&str, UsageError> {
        match self.positionals.as_slice() {
            [f] => Ok(f),
            [] => Err(UsageError(msg("missing-file", &[("command", command)]))),
            [_, extra, ..] => Err(UsageError(msg("extra-argument", &[("argument", extra)]))),
        }
    }

    /// At most one positional file argument.
    pub fn optional_file(&self) -> Result<Option<&str>, UsageError> {
        match self.positionals.as_slice() {
            [] => Ok(None),
            [f] => Ok(Some(f)),
            [_, extra, ..] => Err(UsageError(msg("extra-argument", &[("argument", extra)]))),
        }
    }

    /// A required flag's value.
    pub fn required(&self, command: &str, flag: &str) -> Result<&str, UsageError> {
        self.value(flag).ok_or_else(|| UsageError(msg("missing-flag", &[("command", command), ("flag", flag)])))
    }
}
