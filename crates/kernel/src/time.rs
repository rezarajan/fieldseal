//! Time values. The kernel never reads a clock: times arrive through ports.

/// Authority time, in milliseconds since the Unix epoch, UTC (WIRE-008), as stated in an
/// authority-signed artefact or read from an authority-side clock port.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct AuthorityTime(pub u64);

impl AuthorityTime {
    /// One second, in milliseconds.
    pub const SECOND: u64 = 1_000;
    /// One day, in milliseconds.
    pub const DAY: u64 = 86_400 * Self::SECOND;

    /// The milliseconds since the epoch.
    pub fn as_millis(self) -> u64 {
        self.0
    }

    /// This time plus `millis`, or `None` on overflow.
    pub fn checked_add(self, millis: u64) -> Option<Self> {
        self.0.checked_add(millis).map(Self)
    }
}

/// A reading of a device's monotonic clock (ADR 0020).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ElapsedReading {
    /// Milliseconds since boot, from the platform's monotonic clock.
    pub elapsed_ms: u64,
    /// The platform's boot counter.
    pub boot_count: u32,
}

/// A record's monotonic time: the latest anchor, slots since it, and the boot count.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Tick {
    /// Digest of the anchor that started the current epoch.
    pub anchor: crate::id::Digest,
    /// Milliseconds counted since that anchor, never decreasing.
    pub slot_ms: u64,
    /// Boot count when the tick was taken.
    pub boot_count: u32,
}
