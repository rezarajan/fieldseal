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

use std::io::Write as _;
use std::path::{Path, PathBuf};

use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
use fieldseal_intake::ports::{RosterHistory, RosterHistoryError};
use fieldseal_kernel::id::{CohortId, Digest, SubjectId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;

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

/// Appends `roster` to the tenancy's file.
pub fn record_issued(dir: &Path, tenancy: &TenancyId, roster: &IssuedRoster) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut text = format!("roster {} {} {} {}\n", roster.cohort.as_str(), roster.version, fieldseal_kernel::digest::lower_hex(roster.address.as_bytes()), roster.issued_at.0);
    for (s, c) in &roster.consent {
        text.push_str(&format!("consent {}={}\n", s.as_str(), consent_name(*c)));
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(file(dir, tenancy))?;
    f.write_all(text.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(file(dir, tenancy), std::fs::Permissions::from_mode(0o644));
    }
    Ok(())
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

fn parse(text: &str) -> Option<Vec<IssuedRoster>> {
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
                _ => IssuedConsent::Unknown,
            };
            out.last_mut()?.consent.insert(SubjectId::new(s).ok()?, c);
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
