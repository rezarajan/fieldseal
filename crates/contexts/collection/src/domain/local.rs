//! The local record: the readable copy of the tenancy's records, folded into current state
//! per subject (COL §2, COL-052, COL-061).
//!
//! Each entry's plaintext is the record payload (WIRE-080), except that an `evidence`
//! payload's `bytes` are emptied: the local record notes only that evidence exists
//! (COL-043). Alongside each entry the runtime keeps a [`LocalNote`] (the record ID and how
//! long the capture took, for the `timing` field check), encrypted the same way.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::error::WireError;
use fieldseal_kernel::id::{Fingerprint, RecordId, Seq};
use fieldseal_kernel::payload::Mode;
use fieldseal_kernel::structure::Fields;

use super::payload::{Payload, StatusCode};

/// Local bookkeeping for one record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LocalNote {
    /// The record's ID (from its header).
    pub record_id: RecordId,
    /// Milliseconds from the start of the capture to sealing, for `items` records.
    pub capture_ms: Option<u64>,
}

impl LocalNote {
    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![("record_id", Value::Bytes(self.record_id.as_bytes().to_vec()))];
        if let Some(ms) = self.capture_ms {
            entries.push(("capture_ms", Value::Int(i128::from(ms))));
        }
        cbor::encode(&cbor::map(entries)).expect("encodable")
    }

    /// Reads a note.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode(bytes)?)?;
        let n = Self {
            record_id: RecordId::from(f.bytes_n::<16>("record_id")?),
            capture_ms: f.take_opt("capture_ms").map(fieldseal_kernel::structure::expect_uint).transpose()?,
        };
        f.finish()?;
        Ok(n)
    }
}

/// One decrypted local record entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LocalEntryView {
    /// The record's `seq`.
    pub seq: Seq,
    /// The payload (evidence bytes emptied).
    pub payload: Payload,
    /// The note.
    pub note: LocalNote,
}

/// A subject's current state: records folded in `seq` order, last write wins per item
/// (COL-061).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SubjectState {
    /// Current item values.
    pub current: BTreeMap<String, Value>,
    /// Soft verdicts kept with a reason: item path to reason (COL-063).
    pub overrides: BTreeMap<String, String>,
    /// Soft rules raised when records were sealed.
    pub flags: BTreeSet<String>,
    /// Every record about the subject, in `seq` order.
    pub records: Vec<Seq>,
    /// The `items` records, in `seq` order.
    pub items: Vec<Seq>,
    /// The latest status recorded.
    pub status: Option<StatusCode>,
    /// The latest consent record's ID.
    pub consent_record: Option<RecordId>,
    /// The modes of the `items` records, in order.
    pub modes: Vec<Mode>,
    /// Total capture time of its `items` records, in milliseconds.
    pub capture_ms: u64,
}

fn retracted(v: &Value) -> bool {
    v.as_map().is_some_and(|m| m.len() == 1 && m.get("retracted") == Some(&Value::Bool(true)))
}

/// Who a state is about: the subject, bytes as sealed, and the instrument. A person surveyed with
/// two instruments has two states, since their item paths are not one namespace.
pub type StateKey = (Vec<u8>, Fingerprint);

/// Folds local record entries into the current state of each subject and instrument.
pub fn fold(entries: &[LocalEntryView]) -> BTreeMap<StateKey, SubjectState> {
    let mut sorted: Vec<&LocalEntryView> = entries.iter().collect();
    sorted.sort_by_key(|e| e.seq);
    let mut out: BTreeMap<StateKey, SubjectState> = BTreeMap::new();
    for e in sorted {
        let (Some(subject), Some(instrument)) = (e.payload.subject(), e.payload.instrument()) else { continue };
        let s = out.entry((subject.to_vec(), *instrument)).or_default();
        s.records.push(e.seq);
        match &e.payload {
            Payload::Items(p) => {
                s.items.push(e.seq);
                s.modes.push(p.mode);
                s.capture_ms += e.note.capture_ms.unwrap_or(0);
                for (k, v) in &p.values {
                    if retracted(v) {
                        s.current.remove(k.as_str());
                        s.overrides.remove(k.as_str());
                    } else {
                        s.current.insert(k.as_str().to_owned(), v.clone());
                    }
                }
                if let Some(o) = &p.overrides {
                    for (k, r) in o {
                        s.overrides.insert(k.as_str().to_owned(), r.clone());
                    }
                }
                if let Some(f) = &p.flags {
                    s.flags.extend(f.iter().cloned());
                }
            }
            Payload::Status { status, .. } => s.status = Some(*status),
            Payload::Consent { .. } => s.consent_record = Some(e.note.record_id),
            _ => {}
        }
    }
    out
}

