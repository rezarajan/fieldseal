//! Wrong-PIN accounting (COL-023, ADR 0017).
//!
//! The counter is persisted, wrapped by the hardware wrapping key so it can't be edited or
//! reset by another user of the device without detection. Waits are measured on the
//! monotonic clock; a reboot restarts the current wait in full rather than letting the
//! collector skip it.

use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::error::WireError;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::time::ElapsedReading;

/// Consecutive wrong PIN entries and the wait they impose.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PinAttempts {
    /// Consecutive failures since the last correct PIN.
    pub failures: u64,
    /// The current wait, in milliseconds, if any.
    pub wait_ms: u64,
    /// When the wait started.
    pub wait_from: Option<ElapsedReading>,
}

impl PinAttempts {
    /// Milliseconds still to wait at `now`, or `None`. A wait that started in an earlier
    /// boot restarts from `now` (the caller persists the result).
    pub fn remaining(&mut self, now: ElapsedReading) -> Option<u64> {
        let from = self.wait_from?;
        if from.boot_count != now.boot_count {
            self.wait_from = Some(now);
            return Some(self.wait_ms);
        }
        let left = (from.elapsed_ms + self.wait_ms).saturating_sub(now.elapsed_ms);
        if left == 0 {
            self.wait_from = None;
            self.wait_ms = 0;
            None
        } else {
            Some(left)
        }
    }

    /// Records a failure; `delay` is the wait runtime policy imposes after `failures`.
    pub fn fail(&mut self, now: ElapsedReading, delay: impl Fn(u64) -> Option<u64>) {
        self.failures += 1;
        match delay(self.failures) {
            Some(ms) if ms > 0 => {
                self.wait_ms = ms;
                self.wait_from = Some(now);
            }
            _ => {
                self.wait_ms = 0;
                self.wait_from = None;
            }
        }
    }

    /// Records a correct PIN.
    pub fn succeed(&mut self) {
        *self = Self::default();
    }

    /// The state as canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![("failures", Value::Int(i128::from(self.failures))), ("wait_ms", Value::Int(i128::from(self.wait_ms)))];
        if let Some(r) = self.wait_from {
            entries.push(("from_ms", Value::Int(i128::from(r.elapsed_ms))));
            entries.push(("from_boot", Value::Int(i128::from(r.boot_count))));
        }
        cbor::encode(&cbor::map(entries)).expect("encodable")
    }

    /// Reads the state.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode(bytes)?)?;
        let failures = f.uint("failures")?;
        let wait_ms = f.uint("wait_ms")?;
        let from_ms = f.take_opt("from_ms").map(fieldseal_kernel::structure::expect_uint).transpose()?;
        let from_boot = f.take_opt("from_boot").map(fieldseal_kernel::structure::expect_uint).transpose()?;
        f.finish()?;
        let wait_from = match (from_ms, from_boot) {
            (Some(ms), Some(b)) => Some(ElapsedReading {
                elapsed_ms: ms,
                boot_count: u32::try_from(b).map_err(|_| WireError::new(fieldseal_kernel::ErrorCode::UnknownField, 0, "from_boot out of range"))?,
            }),
            (None, None) => None,
            _ => return Err(WireError::new(fieldseal_kernel::ErrorCode::UnknownField, 0, "from_ms and from_boot go together")),
        };
        Ok(Self { failures, wait_ms, wait_from })
    }
}

