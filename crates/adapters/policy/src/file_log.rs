//! A file-backed, append-only, hash-chained decision log (POL-040; `DecisionLog` port).
//!
//! # Format
//!
//! One JSON object per line:
//!
//! ```text
//! {"index":0,"prev":"<64 hex>","record":"<hex of the canonical CBOR record>","hash":"<64 hex>"}
//! ```
//!
//! `hash` is SHA-256 over `"fieldseal.policy.decision-log.v1\0" || index (8 bytes, big
//! endian) || prev (32 bytes) || record bytes`, and `prev` is the previous entry's `hash`
//! (32 zero bytes for the first). Changing, removing, inserting or reordering any entry
//! therefore breaks every hash after it, and [`FileDecisionLog::verify`] finds the first
//! entry that does not fit.
//!
//! # What this does and does not give
//!
//! The chain makes edits in the middle of the log evident. It cannot, on its own, show that
//! entries were cut off the end, because a shorter log is still a valid chain. For that,
//! [`FileDecisionLog::head`] returns the length and last hash, which an operator records
//! somewhere the log's writer cannot reach (a transparency log, a ticket, another host), and
//! [`FileDecisionLog::verify_against`] checks the file still extends that head.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::{lower_hex, sha256_parts};
use fieldseal_kernel::id::{ContentAddress, Digest, RecordId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_policy::domain::{Decision, DecisionPoint, DecisionRecord, Obligation, Subject, Verdict};
use fieldseal_policy::ports::{DecisionLog, DecisionLogError};
use serde_json::{Value as Json, json};

const DOMAIN: &[u8] = b"fieldseal.policy.decision-log.v1\0";
const GENESIS: [u8; 32] = [0; 32];

/// Where the log's chain stands: how many entries, and the last entry's hash (all zeros when
/// empty). Record it elsewhere to detect later truncation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Head {
    /// The number of entries.
    pub len: u64,
    /// The last entry's hash.
    pub hash: [u8; 32],
}

/// Why a log failed its integrity check, naming the first bad entry.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum IntegrityError {
    /// The file could not be read.
    #[error("decision log unreadable: {0}")]
    Unreadable(String),
    /// A line is not a well-formed entry.
    #[error("entry {index}: malformed ({why})")]
    Malformed {
        /// The line's position.
        index: u64,
        /// What is wrong.
        why: String,
    },
    /// An entry carries the wrong index (removed, inserted or reordered entries).
    #[error("entry {index}: expected index {expected}")]
    WrongIndex {
        /// The entry's recorded index.
        index: u64,
        /// The index its position requires.
        expected: u64,
    },
    /// An entry does not chain from the one before it.
    #[error("entry {index}: does not chain from the previous entry")]
    BrokenChain {
        /// The entry.
        index: u64,
    },
    /// An entry's hash does not match its content.
    #[error("entry {index}: hash does not match its content")]
    BadHash {
        /// The entry.
        index: u64,
    },
    /// The log is shorter than, or diverges from, a head recorded earlier.
    #[error("the log no longer extends the recorded head ({0})")]
    HeadMismatch(String),
}

fn put_verdict(v: Verdict) -> &'static str {
    v.name()
}

fn obligation_name(o: Obligation) -> &'static str {
    match o {
        Obligation::SampleForReview => "sample-for-review",
        Obligation::PauseRelease => "pause-release",
        Obligation::Quarantine => "quarantine",
    }
}

fn bytes(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}

/// The canonical encoding of a record.
fn encode_record(r: &DecisionRecord) -> Vec<u8> {
    let (kind, id) = match &r.subject {
        Subject::Tenancy(t) => ("tenancy", bytes(t.as_bytes())),
        Subject::Registration(s) => ("registration", Value::Text(s.clone())),
        Subject::Record(id) => ("record", bytes(id.as_bytes())),
    };
    let mut fields = vec![
        ("point", Value::Text(r.decision.point.name().to_owned())),
        ("verdict", Value::Text(put_verdict(r.decision.verdict).to_owned())),
        ("reasons", Value::Array(r.decision.reasons.iter().map(|s| Value::Text(s.clone())).collect())),
        ("obligations", Value::Array(r.decision.obligations.iter().map(|o| Value::Text(obligation_name(*o).to_owned())).collect())),
        ("policy", Value::Array(r.decision.policy.iter().map(|a| bytes(a.as_bytes())).collect())),
        ("input", bytes(r.input_digest.as_bytes())),
        ("subject", cbor::map([("kind", Value::Text(kind.to_owned())), ("id", id)])),
        ("at", Value::Int(i128::from(r.at.0))),
    ];
    if let Some(resolves) = r.resolves {
        fields.push(("resolves", Value::Int(i128::from(resolves))));
    }
    cbor::encode(&cbor::map(fields)).expect("a decision record is plain values")
}

/// Whether `m` has every `required` key and no key beyond `required` and `optional`.
fn closed(m: &std::collections::BTreeMap<String, Value>, required: &[&str], optional: &[&str]) -> Option<()> {
    let ok = required.iter().all(|k| m.contains_key(*k)) && m.keys().all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()));
    ok.then_some(())
}

fn decode_record(raw: &[u8]) -> Option<DecisionRecord> {
    let value = cbor::decode(raw).ok()?;
    let m = value.as_map()?;
    closed(m, &["point", "verdict", "reasons", "obligations", "policy", "input", "subject", "at"], &["resolves"])?;
    let text = |k: &str| m.get(k)?.as_text();
    let fixed = |v: &Value| -> Option<[u8; 32]> {
        match v {
            Value::Bytes(b) => b.as_slice().try_into().ok(),
            _ => None,
        }
    };
    let point = DecisionPoint::parse(text("point")?)?;
    let verdict = [Verdict::Allow, Verdict::Deny, Verdict::Hold, Verdict::Flag].into_iter().find(|v| v.name() == text("verdict").unwrap_or(""))?;
    let reasons = m.get("reasons")?.as_array()?.iter().map(|v| v.as_text().map(str::to_owned)).collect::<Option<Vec<_>>>()?;
    let obligations = m
        .get("obligations")?
        .as_array()?
        .iter()
        .map(|v| match v.as_text()? {
            "sample-for-review" => Some(Obligation::SampleForReview),
            "pause-release" => Some(Obligation::PauseRelease),
            "quarantine" => Some(Obligation::Quarantine),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let policy = m.get("policy")?.as_array()?.iter().map(|v| fixed(v).map(ContentAddress::from)).collect::<Option<Vec<_>>>()?;
    let subject = m.get("subject")?.as_map()?;
    closed(subject, &["kind", "id"], &[])?;
    let id = subject.get("id")?;
    let subject = match subject.get("kind")?.as_text()? {
        "tenancy" => Subject::Tenancy(TenancyId::from(fixed(id)?)),
        "registration" => Subject::Registration(id.as_text()?.to_owned()),
        "record" => match id {
            Value::Bytes(b) => Subject::Record(RecordId::from_bytes(b).ok()?),
            _ => return None,
        },
        _ => return None,
    };
    let at = AuthorityTime(u64::try_from(m.get("at")?.as_int()?).ok()?);
    let resolves = match m.get("resolves") {
        Some(v) => Some(u64::try_from(v.as_int()?).ok()?),
        None => None,
    };
    Some(DecisionRecord {
        decision: Decision { point, verdict, reasons, obligations, policy },
        input_digest: Digest::from(fixed(m.get("input")?)?),
        subject,
        at,
        resolves,
    })
}

fn entry_hash(index: u64, prev: &[u8; 32], record: &[u8]) -> [u8; 32] {
    *sha256_parts(&[DOMAIN, &index.to_be_bytes(), prev, record]).as_bytes()
}

/// Decodes lowercase hexadecimal only: no sign, no upper case, no odd length.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

/// One entry as read from the file, already checked against its position and the chain.
struct Verified {
    record: Vec<u8>,
    hash: [u8; 32],
}

/// Reads and checks every entry of `text`, stopping at the first bad one. Calls `each` with
/// each good entry; returns the head.
fn walk(text: &str, mut each: impl FnMut(u64, &Verified) -> bool) -> Result<Head, IntegrityError> {
    let mut prev = GENESIS;
    let mut len = 0u64;
    for (position, line) in text.lines().enumerate() {
        let index = position as u64;
        let malformed = |why: &str| IntegrityError::Malformed { index, why: why.to_owned() };
        let json: Json = serde_json::from_str(line).map_err(|e| malformed(&e.to_string()))?;
        let object = json.as_object().ok_or_else(|| malformed("not an object"))?;
        if object.len() != 4 || !["index", "prev", "record", "hash"].iter().all(|k| object.contains_key(*k)) {
            return Err(malformed("an entry has exactly `index`, `prev`, `record` and `hash`"));
        }
        let recorded = json.get("index").and_then(Json::as_u64).ok_or_else(|| malformed("no index"))?;
        let entry_prev = json.get("prev").and_then(Json::as_str).and_then(unhex32).ok_or_else(|| malformed("no prev hash"))?;
        let record = json.get("record").and_then(Json::as_str).and_then(unhex).ok_or_else(|| malformed("no record"))?;
        let hash = json.get("hash").and_then(Json::as_str).and_then(unhex32).ok_or_else(|| malformed("no hash"))?;
        if recorded != index {
            return Err(IntegrityError::WrongIndex { index: recorded, expected: index });
        }
        if entry_prev != prev {
            return Err(IntegrityError::BrokenChain { index });
        }
        if entry_hash(index, &entry_prev, &record) != hash {
            return Err(IntegrityError::BadHash { index });
        }
        if decode_record(&record).is_none() {
            return Err(malformed("the record does not decode"));
        }
        prev = hash;
        len += 1;
        if !each(index, &Verified { record, hash }) {
            break;
        }
    }
    Ok(Head { len, hash: prev })
}

struct State {
    head: Head,
    /// The file's size when we last wrote or checked it, to notice outside changes cheaply.
    size: u64,
}

/// A file-backed [`DecisionLog`]: append-only, each entry hash-chained to the one before.
///
/// Opening verifies the whole file and fails if it does not verify. Appends are written and
/// synced before they return. Each append also checks the file is still the size this process
/// last left it, so a log edited underneath a running writer refuses further appends rather than
/// extending a broken chain; [`FileDecisionLog::verify`] is the full check. Reads verify the
/// chain up to the entry they return.
pub struct FileDecisionLog {
    path: PathBuf,
    state: Mutex<State>,
}

impl FileDecisionLog {
    /// Opens the log at `path`, creating it empty if absent, after verifying every entry.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IntegrityError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            File::create(&path).map_err(|e| IntegrityError::Unreadable(e.to_string()))?;
        }
        let (head, size) = Self::scan(&path)?;
        Ok(Self { path, state: Mutex::new(State { head, size }) })
    }

    fn scan(path: &Path) -> Result<(Head, u64), IntegrityError> {
        let raw = fs::read(path).map_err(|e| IntegrityError::Unreadable(e.to_string()))?;
        let text = String::from_utf8(raw).map_err(|_| IntegrityError::Malformed { index: 0, why: "not UTF-8".to_owned() })?;
        let size = text.len() as u64;
        if !text.is_empty() && !text.ends_with('\n') {
            let index = text.lines().count() as u64 - 1;
            return Err(IntegrityError::Malformed { index, why: "the last entry is cut short".to_owned() });
        }
        Ok((walk(&text, |_, _| true)?, size))
    }

    /// Checks the whole file again and returns its head, or the first entry that fails.
    pub fn verify(&self) -> Result<Head, IntegrityError> {
        Self::scan(&self.path).map(|(head, _)| head)
    }

    /// The chain's current length and last hash, from what this process has written or
    /// verified. Record it out of the writer's reach to detect truncation later.
    pub fn head(&self) -> Head {
        self.state.lock().expect("lock").head
    }

    /// Checks the file verifies and still extends `anchor`: it has at least `anchor.len`
    /// entries and the entry at that point hashes as recorded.
    pub fn verify_against(&self, anchor: &Head) -> Result<Head, IntegrityError> {
        let raw = fs::read_to_string(&self.path).map_err(|e| IntegrityError::Unreadable(e.to_string()))?;
        let mut at_anchor = (anchor.len == 0).then_some(GENESIS);
        let head = walk(&raw, |index, e| {
            if index + 1 == anchor.len {
                at_anchor = Some(e.hash);
            }
            true
        })?;
        match at_anchor {
            None => Err(IntegrityError::HeadMismatch(format!("the log has {} entries, the head records {}", head.len, anchor.len))),
            Some(h) if h != anchor.hash => Err(IntegrityError::HeadMismatch("the entry at the recorded length has a different hash".to_owned())),
            Some(_) => Ok(head),
        }
    }
}

fn unavailable(e: impl std::fmt::Display) -> DecisionLogError {
    DecisionLogError::Unavailable(e.to_string())
}

impl DecisionLog for FileDecisionLog {
    fn append(&self, record: &DecisionRecord) -> Result<u64, DecisionLogError> {
        let mut state = self.state.lock().expect("lock");
        let on_disk = fs::metadata(&self.path).map_err(unavailable)?.len();
        if on_disk != state.size {
            return Err(unavailable("the log file was changed outside this writer; run verify"));
        }
        let index = state.head.len;
        let raw = encode_record(record);
        let hash = entry_hash(index, &state.head.hash, &raw);
        let line = json!({"index": index, "prev": lower_hex(&state.head.hash), "record": lower_hex(&raw), "hash": lower_hex(&hash)});
        let mut text = line.to_string();
        text.push('\n');
        let mut file = OpenOptions::new().append(true).open(&self.path).map_err(unavailable)?;
        file.write_all(text.as_bytes()).map_err(unavailable)?;
        file.sync_data().map_err(unavailable)?;
        state.head = Head { len: index + 1, hash };
        state.size += text.len() as u64;
        Ok(index)
    }

    fn read(&self, index: u64) -> Result<DecisionRecord, DecisionLogError> {
        let raw = fs::read_to_string(&self.path).map_err(unavailable)?;
        let mut found = None;
        let walked = walk(&raw, |i, e| {
            if i == index {
                found = Some(e.record.clone());
                return false;
            }
            true
        });
        // A bad entry before or at `index` is an integrity failure, not "not found".
        walked.map_err(unavailable)?;
        let bytes = found.ok_or(DecisionLogError::NotFound)?;
        decode_record(&bytes).ok_or_else(|| unavailable("the record does not decode"))
    }

    fn len(&self) -> u64 {
        self.state.lock().expect("lock").head.len
    }
}
