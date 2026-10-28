//! Policy value types: durations, sizes, dates and versions (POL-003).

use std::fmt;

/// A length of time with whole-second resolution, written as an integer and a unit
/// (`s`, `m`, `h` or `d`), for example `10m`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Duration(u64);

impl Duration {
    /// A duration of `seconds`.
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// A duration of `minutes`.
    pub const fn from_mins(minutes: u64) -> Self {
        Self(minutes * 60)
    }

    /// The length in whole seconds.
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Parses `<integer><s|m|h|d>`; zero and overflow are refused.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || {
            format!("`{text}` is not a duration; write an integer and s, m, h or d (for example 10m)")
        };
        let unit = text.chars().last().ok_or_else(bad)?;
        let multiplier: u64 = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => return Err(bad()),
        };
        let digits = &text[..text.len() - 1];
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let n: u64 = digits.parse().map_err(|_| bad())?;
        if n == 0 {
            return Err(format!("`{text}` must be greater than zero"));
        }
        n.checked_mul(multiplier).map(Self).ok_or_else(bad)
    }
}

impl fmt::Display for Duration {
    /// The largest unit that divides the duration exactly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        if s != 0 && s.is_multiple_of(86_400) {
            write!(f, "{}d", s / 86_400)
        } else if s != 0 && s.is_multiple_of(3600) {
            write!(f, "{}h", s / 3600)
        } else if s != 0 && s.is_multiple_of(60) {
            write!(f, "{}m", s / 60)
        } else {
            write!(f, "{s}s")
        }
    }
}

/// A size in bytes, written as an integer and `KiB`, `MiB` or `GiB`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ByteSize(u64);

impl ByteSize {
    /// `n` kibibytes.
    pub const fn kib(n: u64) -> Self {
        Self(n * 1024)
    }

    /// `n` mebibytes.
    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }

    /// The size in bytes.
    pub const fn as_bytes(self) -> u64 {
        self.0
    }

    /// Parses `<integer><KiB|MiB|GiB>`; zero and overflow are refused.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || {
            format!("`{text}` is not a size; write an integer and KiB, MiB or GiB (for example 64MiB)")
        };
        let (digits, multiplier) = if let Some(d) = text.strip_suffix("KiB") {
            (d, 1024u64)
        } else if let Some(d) = text.strip_suffix("MiB") {
            (d, 1024 * 1024)
        } else if let Some(d) = text.strip_suffix("GiB") {
            (d, 1024 * 1024 * 1024)
        } else {
            return Err(bad());
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let n: u64 = digits.parse().map_err(|_| bad())?;
        if n == 0 {
            return Err(format!("`{text}` must be greater than zero"));
        }
        n.checked_mul(multiplier).map(Self).ok_or_else(bad)
    }
}

impl fmt::Display for ByteSize {
    /// The largest unit that divides the size exactly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        if b != 0 && b.is_multiple_of(1 << 30) {
            write!(f, "{}GiB", b >> 30)
        } else if b != 0 && b.is_multiple_of(1 << 20) {
            write!(f, "{}MiB", b >> 20)
        } else {
            write!(f, "{}KiB", b.div_ceil(1024))
        }
    }
}

/// A calendar date, `YYYY-MM-DD`. Ordered chronologically.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Date {
    /// The year.
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month.
    pub day: u8,
}

impl Date {
    /// Parses `YYYY-MM-DD`, checking the day against the month.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || format!("`{text}` is not a date; write YYYY-MM-DD");
        let b = text.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return Err(bad());
        }
        let digits_ok = b
            .iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
        if !digits_ok {
            return Err(bad());
        }
        let year: u16 = text[0..4].parse().map_err(|_| bad())?;
        let month: u8 = text[5..7].parse().map_err(|_| bad())?;
        let day: u8 = text[8..10].parse().map_err(|_| bad())?;
        let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return Err(bad()),
        };
        if year == 0 || day == 0 || day > days {
            return Err(bad());
        }
        Ok(Self { year, month, day })
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// A `major.minor.patch` version. Ordered numerically. Pre-release and build parts are not
/// used by policy documents.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Version {
    /// Major.
    pub major: u64,
    /// Minor.
    pub minor: u64,
    /// Patch.
    pub patch: u64,
}

impl Version {
    /// Parses `major.minor.patch` (decimal digits only).
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || format!("`{text}` is not a version; write major.minor.patch");
        let mut parts = text.split('.');
        let mut next = || -> Result<u64, String> {
            let p = parts.next().ok_or_else(bad)?;
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            p.parse().map_err(|_| bad())
        };
        let version = Self {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
