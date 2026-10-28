//! Ticks (ADR 0020, COL-080–COL-083, WIRE-070–WIRE-072): the latest anchor, milliseconds
//! since it by the monotonic clock, and the boot count.
//!
//! [`TickState`] is persisted before each record is appended, so the high-water mark
//! survives a crash or a reboot. When the boot count changes (a reboot, or a clock that
//! restarted), `slot` continues from the high-water mark plus the elapsed time since the
//! new boot (WIRE-072). Every tick's slot is strictly above the previous one under the same
//! anchor (COL-081, WIRE-071).

use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::error::WireError;
use fieldseal_kernel::id::Digest;
use fieldseal_kernel::payload::Tick;
use fieldseal_kernel::structure::{Fields, expect_uint};
use fieldseal_kernel::time::ElapsedReading;

/// The persisted tick clock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TickState {
    /// The latest anchor chained into the journal (or the build anchor).
    pub anchor: Digest,
    /// The boot count the base was taken in.
    pub boot: u32,
    /// The slot at `elapsed_base`.
    pub slot_base: u64,
    /// The elapsed reading the base was taken at.
    pub elapsed_base: u64,
    /// The highest slot issued under `anchor`.
    pub high_water: Option<u64>,
}

impl TickState {
    /// A clock starting at `anchor` now.
    pub fn new(anchor: Digest, now: ElapsedReading) -> Self {
        Self { anchor, boot: now.boot_count, slot_base: 0, elapsed_base: now.elapsed_ms, high_water: None }
    }

    /// The next tick, advancing the high-water mark. `wall` is the untrusted wall-clock hint.
    pub fn next(&mut self, now: ElapsedReading, wall: Option<u64>) -> Tick {
        if now.boot_count != self.boot {
            // A new boot: the monotonic clock restarted, so continue from the high-water mark.
            self.slot_base = self.high_water.map_or(0, |h| h + 1);
            self.elapsed_base = 0;
            self.boot = now.boot_count;
        }
        let mut slot = self.slot_base + now.elapsed_ms.saturating_sub(self.elapsed_base);
        if let Some(h) = self.high_water
            && slot <= h
        {
            slot = h + 1;
        }
        self.high_water = Some(slot);
        Tick { anchor: self.anchor, slot, boot: u64::from(now.boot_count), wall }
    }

    /// Restarts the clock at a newly chained anchor (COL-082): later ticks count from it.
    pub fn rebase(&mut self, anchor: Digest, now: ElapsedReading) {
        *self = Self::new(anchor, now);
    }

    /// The state as a value, for storage.
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            ("anchor", Value::Bytes(self.anchor.as_bytes().to_vec())),
            ("boot", Value::Int(i128::from(self.boot))),
            ("slot_base", Value::Int(i128::from(self.slot_base))),
            ("elapsed_base", Value::Int(i128::from(self.elapsed_base))),
        ];
        if let Some(h) = self.high_water {
            entries.push(("high_water", Value::Int(i128::from(h))));
        }
        cbor::map(entries)
    }

    /// Reads a stored state.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let s = Self {
            anchor: Digest::from(f.bytes_n::<32>("anchor")?),
            boot: u32::try_from(f.uint("boot")?).unwrap_or(u32::MAX),
            slot_base: f.uint("slot_base")?,
            elapsed_base: f.uint("elapsed_base")?,
            high_water: f.take_opt("high_water").map(expect_uint).transpose()?,
        };
        f.finish()?;
        Ok(s)
    }
}

/// Checks that ticks strictly increase along a journal (COL-081, WIRE-071): each anchor is
/// either the previous record's or a later one, and under the same anchor the slot rises.
/// `anchor_position` gives each anchor's position in the chain. Returns the index of the
/// first tick that breaks the order.
pub fn first_non_monotonic(ticks: &[Tick], anchor_position: impl Fn(&Digest) -> Option<usize>) -> Option<usize> {
    ticks.windows(2).position(|w| {
        let (a, b) = (&w[0], &w[1]);
        match (anchor_position(&a.anchor), anchor_position(&b.anchor)) {
            (Some(pa), Some(pb)) if pb > pa => false,
            (Some(pa), Some(pb)) if pb == pa => b.slot <= a.slot,
            _ => true,
        }
    })
    .map(|i| i + 1)
}
