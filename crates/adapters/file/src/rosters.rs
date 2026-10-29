//! The rosters the authority issued to each tenancy, kept in a directory so that another
//! process (the intake endpoint) can check consent against them: one text file per tenancy,
//! `<tenancy hex>.rosters`, appended to when a bundle with a roster is built.
//!
//! ```text
//! roster <cohort> <version> <address hex> <issued-at ms>
//! consent <subject>=<granted|refused|unknown>
//! ```
//!
//! Development only. The roster contents (display names, attributes) are not kept here, only
//! each subject's consent state, which is what the gate needs (INT-040–INT-045).

use std::path::{Path, PathBuf};

use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
use fieldseal_intake::ports::{RosterHistory, RosterHistoryError};
use fieldseal_kernel::id::{CohortId, Digest, SubjectId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

use crate::atomic::write_atomic_mode;

fn file(dir: &Path, tenancy: &TenancyId) -> PathBuf {
    dir.join(format!("{}.rosters", fieldseal_kernel::digest::lower_hex(tenancy.as_bytes())))
}

fn consent_name(c: IssuedConsent) -> &'static str {
    match c {
        IssuedConsent::Granted => "granted",
        IssuedConsent::Refused => "refused",
        IssuedConsent::Unknown => "unknown",
    }
}

/// Creates `dir` owner-only, or checks an existing one is. The files hold each subject's
/// consent, so a directory that group or others can reach is refused rather than narrowed:
/// it may be a shared mount the operator set up (as the roster store does).
fn private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{} has mode {mode:03o}; issued rosters need 700 or narrower", dir.display()),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// Adds `roster` to the tenancy's file. The file is rewritten whole (read, append in memory,
/// write a temporary file, sync, rename), so a crash leaves the old file or the new one and
/// never a torn tail. A file that does not parse is left alone and reported, since appending
/// to it would bury the damage.
pub fn record_issued(dir: &Path, tenancy: &TenancyId, roster: &IssuedRoster) -> std::io::Result<()> {
    private_dir(dir)?;
    let path = file(dir, tenancy);
    let mut text = match std::fs::read_to_string(&path) {
        Ok(t) if parse(&t).is_some() => t,
        Ok(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed roster file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    text.push_str(&format!("roster {} {} {} {}\n", roster.cohort.as_str(), roster.version, fieldseal_kernel::digest::lower_hex(roster.address.as_bytes()), roster.issued_at.0));
    for (s, c) in &roster.consent {
        text.push_str(&format!("consent {}={}\n", s.as_str(), consent_name(*c)));
    }
    // Synced before it returns: the reconciler writes the bundle only after this.
    write_atomic_mode(&path, text.as_bytes(), 0o600)
}

/// The issued rosters in a directory, read on each lookup.
pub struct FileRosterHistory {
    dir: PathBuf,
}

impl FileRosterHistory {
    /// The history in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

/// The rosters in `text`, or `None` if any of it is not a whole, known line: an unknown line,
/// an unknown consent word, or a last line cut short (every line ends in a newline).
fn parse(text: &str) -> Option<Vec<IssuedRoster>> {
    if !text.is_empty() && !text.ends_with('\n') {
        return None;
    }
    let mut out: Vec<IssuedRoster> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("roster ") {
            let p: Vec<&str> = rest.split(' ').collect();
            let [cohort, version, address, issued] = p[..] else { return None };
            let address = Digest::from_bytes(&(0..address.len() / 2).map(|i| u8::from_str_radix(address.get(2 * i..2 * i + 2)?, 16).ok()).collect::<Option<Vec<u8>>>()?).ok()?;
            out.push(IssuedRoster { cohort: CohortId::new(cohort).ok()?, version: version.parse().ok()?, address, issued_at: AuthorityTime(issued.parse().ok()?), consent: Default::default() });
        } else if let Some(rest) = line.strip_prefix("consent ") {
            let (s, c) = rest.split_once('=')?;
            let c = match c {
                "granted" => IssuedConsent::Granted,
                "refused" => IssuedConsent::Refused,
                "unknown" => IssuedConsent::Unknown,
                _ => return None,
            };
            out.last_mut()?.consent.insert(SubjectId::new(s).ok()?, c);
        } else {
            return None;
        }
    }
    out.sort_by(|a, b| (&a.cohort, a.version).cmp(&(&b.cohort, b.version)));
    Some(out)
}

impl RosterHistory for FileRosterHistory {
    fn issued(&self, tenancy: &TenancyId) -> Result<Vec<IssuedRoster>, RosterHistoryError> {
        match std::fs::read_to_string(file(&self.dir, tenancy)) {
            Ok(t) => parse(&t).ok_or_else(|| RosterHistoryError::Unavailable("malformed roster file".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(RosterHistoryError::Unavailable(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FileRosterHistory, file, record_issued};
    use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
    use fieldseal_intake::ports::RosterHistory as _;
    use fieldseal_kernel::id::{CohortId, Digest, SubjectId, TenancyId};
    use fieldseal_kernel::time::AuthorityTime;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fieldseal-rosters-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn roster(version: u64) -> IssuedRoster {
        IssuedRoster {
            cohort: CohortId::new("cohort-a").expect("cohort"),
            version,
            address: Digest::from([version as u8; 32]),
            issued_at: AuthorityTime(1_000),
            consent: [(SubjectId::new("s-1").expect("subject"), IssuedConsent::Granted)].into_iter().collect(),
        }
    }

    // covers: INT-040
    #[test]
    fn a_recorded_roster_reads_back_and_a_second_is_added() {
        let dir = scratch("roundtrip");
        let t = TenancyId::from([1; 32]);
        record_issued(&dir, &t, &roster(1)).expect("first");
        record_issued(&dir, &t, &roster(2)).expect("second");
        let got = FileRosterHistory::new(&dir).issued(&t).expect("read");
        assert_eq!(got, vec![roster(1), roster(2)]);
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-040
    #[test]
    fn a_file_cut_short_is_an_error_and_is_not_added_to() {
        let dir = scratch("torn");
        let t = TenancyId::from([1; 32]);
        record_issued(&dir, &t, &roster(1)).expect("first");
        let path = file(&dir, &t);
        let whole = std::fs::read(&path).expect("read");
        // Every cut that is not at a line end, and the cut after the roster line (a roster
        // with its consent lines missing is still a whole file, so it is not tested here).
        for cut in (1..whole.len()).filter(|&i| whole[i - 1] != b'\n') {
            std::fs::write(&path, &whole[..cut]).expect("truncate");
            let err = FileRosterHistory::new(&dir).issued(&t).expect_err("torn");
            assert!(!err.to_string().contains("s-1"), "the error names no content: {err}");
            let before = std::fs::read(&path).expect("read");
            assert!(record_issued(&dir, &t, &roster(2)).is_err(), "cut at {cut}");
            assert_eq!(std::fs::read(&path).expect("read"), before, "a refused record leaves the file as it was");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-040
    #[test]
    fn an_unknown_consent_word_is_an_error() {
        let dir = scratch("word");
        let t = TenancyId::from([1; 32]);
        record_issued(&dir, &t, &roster(1)).expect("first");
        let path = file(&dir, &t);
        let text = std::fs::read_to_string(&path).expect("read").replace("=granted", "=maybe");
        std::fs::write(&path, text).expect("write");
        assert!(FileRosterHistory::new(&dir).issued(&t).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-040
    #[cfg(unix)]
    #[test]
    fn the_directory_is_created_owner_only_and_the_file_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("modes");
        let t = TenancyId::from([1; 32]);
        record_issued(&dir, &t, &roster(1)).expect("record");
        assert_eq!(std::fs::metadata(&dir).expect("dir").permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(file(&dir, &t)).expect("file").permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    // covers: INT-040
    #[cfg(unix)]
    #[test]
    fn a_directory_others_can_reach_is_refused_not_narrowed() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("wide");
        std::fs::create_dir_all(&dir).expect("dir");
        for mode in [0o750, 0o705] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let err = record_issued(&dir, &TenancyId::from([1; 32]), &roster(1)).expect_err("wide");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::metadata(&dir).expect("dir").permissions().mode() & 0o777, mode);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
