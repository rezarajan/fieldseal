//! Helpers shared by the command families: running a command with its outcome, reading and
//! writing files, hexadecimal, time and durations, and configuration lookup (flags first, then
//! `FIELDSEAL_*` environment variables, CLI-002).

use std::path::Path;

use fieldseal_adapters_authoring::Format;
use fieldseal_kernel::Value;
use fieldseal_kernel::time::AuthorityTime;

use crate::args::{Args, UsageError};
use crate::messages::msg;
use crate::outcome::{Outcome, exit};

/// The result of a command body: a usage error ends it with exit 2.
pub type Res<T = ()> = Result<T, UsageError>;

/// A usage error with the catalogue message `id`.
pub fn usage(id: &str, vars: &[(&str, &str)]) -> UsageError {
    UsageError(msg(id, vars))
}

/// Parses `raw` for `command`, runs `body` and emits the outcome. Returns the exit code.
pub fn run_command(
    command: &'static str,
    raw: &[String],
    valued: &[&str],
    switches: &[&str],
    body: impl FnOnce(&Args, &mut Outcome) -> Res,
) -> u8 {
    let mut out = Outcome::new(command);
    let as_json = raw.iter().any(|a| a == "--json");
    let args = match Args::parse(command, raw, valued, switches) {
        Ok(a) => a,
        Err(UsageError(m)) => {
            out.error(exit::USAGE, m);
            return out.emit(as_json);
        }
    };
    if args.has("--help") {
        out.lines.push(msg("usage", &[]));
        return out.emit(as_json);
    }
    if let Err(UsageError(m)) = body(&args, &mut out) {
        out.error(exit::USAGE, m);
    }
    out.emit(as_json)
}

/// The value of `flag`, else of the environment variable `env`. A variable that is set but
/// empty is refused at start-up (`Config::from_lookup`, CLI-030), never treated as unset.
pub fn setting(args: &Args, flag: &str, env: &str) -> Option<String> {
    args.value(flag).map(str::to_owned).or_else(|| std::env::var(env).ok())
}

/// Records an error with the catalogue message `id` and exit code `code`.
pub fn fail(out: &mut Outcome, code: u8, id: &str, vars: &[(&str, &str)]) {
    out.error(code, msg(id, vars));
}

/// Reads a file; on failure records exit 4 (not found).
pub fn read(path: &str, out: &mut Outcome) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) => {
            fail(out, exit::NOT_FOUND, "not-found", &[("file", path), ("reason", &e.to_string())]);
            None
        }
    }
}

/// Writes a file (creating its directory); `private` makes it readable by the owner only.
/// On failure records exit 3.
pub fn write(path: &Path, bytes: &[u8], private: bool, out: &mut Outcome) -> bool {
    let name = path.to_string_lossy().into_owned();
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        fail(out, exit::CONFIG, "write-failed", &[("file", &name), ("reason", &e.to_string())]);
        return false;
    }
    if let Err(e) = std::fs::write(path, bytes) {
        fail(out, exit::CONFIG, "write-failed", &[("file", &name), ("reason", &e.to_string())]);
        return false;
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = private;
    true
}

/// Reads and decodes a YAML or JSON authoring document. A file that does not decode is a
/// finding (exit 1); a missing one is exit 4.
pub fn load_doc(path: &str, out: &mut Outcome) -> Res<Option<Value>> {
    let ext = Path::new(path).extension().and_then(|e| e.to_str()).unwrap_or("");
    let Some(format) = Format::from_extension(ext) else {
        return Err(usage("bad-extension", &[("file", path)]));
    };
    let Some(bytes) = read(path, out) else { return Ok(None) };
    let _ = (&bytes, format);
    match fieldseal_adapters_authoring::decode_path(Path::new(path)) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            out.raw_finding("INS-002", "error", path, &format!("{}:{}", e.line, e.column), &e.message);
            Ok(None)
        }
    }
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    fieldseal_kernel::digest::lower_hex(bytes)
}

/// An unsigned decimal integer: ASCII digits only (no sign, no whitespace, no separators).
pub fn parse_uint(text: &str) -> Option<u64> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok())?
}

/// Decodes hexadecimal text: an even number of hexadecimal digits and nothing else (no sign,
/// no whitespace, no prefix).
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect()
}

/// A duration such as `365d`, `12h`, `30m` or `10s`, in milliseconds (POL-003 forms): decimal
/// digits (no sign) and one unit.
pub fn parse_duration(text: &str) -> Option<u64> {
    let (digits, per) = [("s", 1_000), ("m", 60_000), ("h", 3_600_000), ("d", 86_400_000)]
        .into_iter()
        .find_map(|(unit, per)| text.strip_suffix(unit).map(|d| (d, per)))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(per)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses `text` as exactly `width` ASCII digits.
fn digits(text: &str, width: usize) -> Option<i64> {
    (text.len() == width && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok())?
}

/// A time as milliseconds since the epoch (digits only), an RFC 3339 UTC time
/// (`2026-01-15T08:00:00Z`) or a date (`2026-01-15`, midnight UTC). Fields have fixed widths,
/// carry no sign, and must name a real calendar date and time of day (no `2026-02-31`).
pub fn parse_time(text: &str) -> Option<AuthorityTime> {
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse::<u64>().ok().map(AuthorityTime);
    }
    let (date, time) = match text.split_once('T') {
        Some((d, t)) => (d, t.strip_suffix('Z')?),
        None => (text, "00:00:00"),
    };
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    let (&[y, m, day], &[hh, mm, ss]) = (<&[&str; 3]>::try_from(&d[..]).ok()?, <&[&str; 3]>::try_from(&t[..]).ok()?);
    let (y, m, day) = (digits(y, 4)?, digits(m, 2)?, digits(day, 2)?);
    let (hh, mm, ss) = (digits(hh, 2)?, digits(mm, 2)?, digits(ss, 2)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in_month = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    let secs = days_from_civil(y, m, day) * 86_400 + hh * 3_600 + mm * 60 + ss;
    u64::try_from(secs).ok().and_then(|s| s.checked_mul(1_000)).map(AuthorityTime)
}

/// The time commands act at: `--at`, else `FIELDSEAL_NOW`, else the system clock. The CLI is
/// the outer layer, so it is where the clock is read; the contexts take the time as a value.
pub fn now(args: &Args) -> Res<AuthorityTime> {
    match setting(args, "--at", "FIELDSEAL_NOW") {
        Some(t) => parse_time(&t).ok_or_else(|| usage("bad-time", &[("value", &t)])),
        None => {
            let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis());
            Ok(AuthorityTime(u64::try_from(ms).unwrap_or(0)))
        }
    }
}

/// Files directly in `path` if it is a directory (sorted), else `path` itself.
pub fn files_in(path: &str) -> Vec<String> {
    let p = Path::new(path);
    if p.is_dir() {
        let mut v: Vec<String> = std::fs::read_dir(p)
            .map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.is_file()).map(|p| p.to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        v.sort();
        v
    } else {
        vec![path.to_owned()]
    }
}

/// A value of `map` as text.
pub fn text<'a>(map: &'a std::collections::BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_text)
}

/// The policy layer files: `--policy` (repeatable), else `FIELDSEAL_POLICY` (comma-separated).
/// An empty path, or an empty segment of the comma-separated list (`a,,b`, `a,`), is refused
/// rather than skipped (CLI-030).
pub fn policy_paths(args: &Args) -> Res<Vec<String>> {
    policy_paths_from(args, std::env::var("FIELDSEAL_POLICY").ok().as_deref())
}

/// [`policy_paths`] with the environment value given.
fn policy_paths_from(args: &Args, env: Option<&str>) -> Res<Vec<String>> {
    let paths: Vec<String> = if args.flags.contains_key("--policy") {
        args.values("--policy").to_vec()
    } else {
        env.map(|v| v.split(',').map(str::to_owned).collect()).unwrap_or_default()
    };
    if paths.iter().any(String::is_empty) {
        return Err(usage("bad-policy-list", &[]));
    }
    Ok(paths)
}

