//! The file-backed, append-only log store.
//!
//! # On-disk layout
//!
//! A log directory holds three files:
//!
//! * `log.dat`: the 8-byte magic `FSTLOG01`, then one record per entry. A record is a
//!   4-byte big-endian length, the entry's canonical CBOR, and a 32-byte chain hash,
//!   `SHA-256(domain || previous chain hash || length || entry)` (the first record chains
//!   from 32 zero bytes). Every append writes one record in one `write`, then `fsync`s the
//!   file before it is acknowledged.
//! * `head`: the latest signed checkpoint note, replaced atomically (temp file, `fsync`,
//!   rename, `fsync` of the directory) after every append. It is the log's own record of
//!   what it has signed: on open the stored entries must reproduce its root.
//! * `lock`: an exclusive advisory lock (`flock`) held for the life of the store, so a
//!   second writer is refused. The operating system releases it when the process dies, so
//!   a crash never leaves a stale lock.
//!
//! # Recovery
//!
//! A crash during an append can leave an incomplete record at the end of `log.dat`. On open
//! such a torn tail (a record cut short, or a last record whose chain hash is wrong while no
//! signed checkpoint covers it) is cut off, as it was never acknowledged. Anything else that
//! does not verify (a bad chain hash before the end, an entry that is not canonical, a head
//! the entries cannot reproduce, a head signed by another key) is corruption or tampering:
//! the store refuses to open (fail closed).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fieldseal_kernel::digest::sha256_parts;
use fieldseal_kernel::id::Digest;
use fieldseal_kernel::sign::SigningKey;
use fieldseal_publishing::domain::merkle::{audit_path, consistency_path, leaf_hash, root};
use fieldseal_publishing::domain::{
    CHECKPOINT_FORMAT, CheckpointBody, ConsistencyProof, InclusionProof, LeafFormat, LogEntry, SignedCheckpoint,
};
use fieldseal_publishing::ports::{LogError, LoggedEntry, TransparencyLog};
use fieldseal_trust::domain::LogPin;

const MAGIC: &[u8; 8] = b"FSTLOG01";
const CHAIN_DOMAIN: &[u8] = b"fieldseal.dev/translog/chain/v1";
/// The longest entry record accepted: a canonical `LogEntry` is under 250 bytes.
const MAX_RECORD: usize = 1024;
/// The most entries one [`FileLogStore::entries`] call returns.
pub const MAX_ENTRIES: usize = 256;

/// Why a log store couldn't be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// A file operation failed.
    #[error("log store I/O: {0}")]
    Io(String),
    /// Another process (or another store in this one) holds the log's writer lock.
    #[error("the log is locked by another writer")]
    Locked,
    /// The stored data does not verify: the log refuses to open.
    #[error("log store corrupt: {0}")]
    Corrupt(String),
    /// The origin is not a usable checkpoint origin.
    #[error("invalid log origin: {0}")]
    Origin(String),
}

impl From<StoreError> for LogError {
    fn from(e: StoreError) -> Self {
        LogError::Unavailable(e.to_string())
    }
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Io(e.to_string())
}

fn corrupt(why: impl Into<String>) -> StoreError {
    StoreError::Corrupt(why.into())
}

fn chain(prev: &Digest, entry: &[u8]) -> Digest {
    sha256_parts(&[CHAIN_DOMAIN, prev.as_bytes(), &(entry.len() as u32).to_be_bytes(), entry])
}

fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir).and_then(|d| d.sync_all()).map_err(io)
}

struct State {
    data: File,
    dir: PathBuf,
    leaves: Vec<Digest>,
    chain: Digest,
}

/// A file-backed, append-only RFC 9162 Merkle log that signs C2SP checkpoints with a key
/// the caller supplies. See the module documentation for the on-disk format and recovery.
///
/// It implements [`TransparencyLog`] directly (for in-process use) and is what the HTTP
/// handler ([`crate::handle`]) serves. Leaf hashes are cached in memory and rebuilt on open.
pub struct FileLogStore {
    origin: String,
    key: SigningKey,
    state: Mutex<State>,
    // Held for its lock: released when the store is dropped or the process dies.
    _lock: File,
}

impl FileLogStore {
    /// Opens (creating if needed) the log in `dir`, named `origin`, signing with `key`.
    ///
    /// Takes the writer lock, replays and verifies the stored entries, cuts off a torn tail
    /// and checks the stored head against the entries and `key`.
    pub fn open(dir: &Path, origin: &str, key: SigningKey) -> Result<Self, StoreError> {
        if origin.is_empty() || origin.len() > 256 || origin.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(StoreError::Origin("must be 1 to 256 characters with no whitespace or control characters".into()));
        }
        std::fs::create_dir_all(dir).map_err(io)?;
        let lock = OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lock")).map_err(io)?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => StoreError::Locked,
            std::fs::TryLockError::Error(e) => io(e),
        })?;

        let mut data = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(dir.join("log.dat")).map_err(io)?;
        let head = read_head(dir, origin, &key)?;
        let (leaves, chain, good_len) = replay(&mut data, head.as_ref().map_or(0, |h| h.size()))?;
        if let Some(head) = &head {
            let size = usize::try_from(head.size()).map_err(|_| corrupt("head size"))?;
            if size > leaves.len() {
                return Err(corrupt("the log has fewer entries than its signed head"));
            }
            if &root(&leaves[..size]) != head.root() {
                return Err(corrupt("the stored entries do not reproduce the signed head"));
            }
        }
        let len = data.metadata().map_err(io)?.len();
        if len != good_len {
            data.set_len(good_len).map_err(io)?;
            data.sync_all().map_err(io)?;
        }
        sync_dir(dir)?;
        Ok(Self { origin: origin.into(), key, state: Mutex::new(State { data, dir: dir.to_owned(), leaves, chain }), _lock: lock })
    }

    /// The log's pin, for a trust bundle (TRU-093).
    pub fn pin(&self) -> LogPin {
        LogPin {
            origin: self.origin.clone(),
            public_key: self.key.public_key().as_bytes().to_vec(),
            format: CHECKPOINT_FORMAT.into(),
        }
    }

    /// The log's origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The number of entries.
    pub fn size(&self) -> u64 {
        self.state.lock().expect("lock").leaves.len() as u64
    }

    fn sign(&self, leaves: &[Digest]) -> SignedCheckpoint {
        SignedCheckpoint::sign(
            CheckpointBody { origin: self.origin.clone(), size: leaves.len() as u64, root: root(leaves), extensions: vec![] },
            &self.origin,
            &self.key,
        )
    }

    /// Appends `entry` durably and returns its logged form. The entry is acknowledged only
    /// after it has been `fsync`ed.
    pub fn append_entry(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError> {
        let bytes = entry.encode();
        let mut st = self.state.lock().expect("lock");
        let next = chain(&st.chain, &bytes);
        let mut record = Vec::with_capacity(bytes.len() + 36);
        record.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        record.extend_from_slice(&bytes);
        record.extend_from_slice(next.as_bytes());
        let end = st.data.seek(SeekFrom::End(0)).map_err(|e| LogError::Unavailable(e.to_string()))?;
        let written = st.data.write_all(&record).and_then(|()| st.data.sync_all());
        if let Err(e) = written {
            // Don't leave a partial record that later appends would sit behind.
            let _ = st.data.set_len(end);
            return Err(LogError::Unavailable(e.to_string()));
        }
        st.chain = next;
        st.leaves.push(leaf_hash(&LeafFormat::Fieldseal.leaf(entry)));
        let index = st.leaves.len() - 1;
        let checkpoint = self.sign(&st.leaves);
        // The record is durable; a failed head write only leaves the head behind the data,
        // which open accepts.
        write_head(&st.dir, checkpoint.note()).map_err(LogError::from)?;
        let inclusion = InclusionProof { leaf_index: index as u64, tree_size: checkpoint.size(), path: audit_path(index, &st.leaves) };
        Ok(LoggedEntry { entry: entry.clone(), leaf: LeafFormat::Fieldseal, inclusion, checkpoint })
    }

    /// The latest signed checkpoint.
    pub fn latest_checkpoint(&self) -> SignedCheckpoint {
        self.sign(&self.state.lock().expect("lock").leaves)
    }

    /// An inclusion proof for `leaf_index` in the tree of the first `tree_size` entries.
    pub fn inclusion_at(&self, leaf_index: u64, tree_size: u64) -> Result<InclusionProof, LogError> {
        let st = self.state.lock().expect("lock");
        let size = usize::try_from(tree_size).map_err(|_| LogError::OutOfRange)?;
        let m = usize::try_from(leaf_index).map_err(|_| LogError::OutOfRange)?;
        if size > st.leaves.len() || m >= size {
            return Err(LogError::OutOfRange);
        }
        Ok(InclusionProof { leaf_index, tree_size, path: audit_path(m, &st.leaves[..size]) })
    }

    /// A consistency proof from the first `old_size` entries to the first `new_size`.
    pub fn consistency_between(&self, old_size: u64, new_size: u64) -> Result<ConsistencyProof, LogError> {
        let st = self.state.lock().expect("lock");
        let new = usize::try_from(new_size).map_err(|_| LogError::OutOfRange)?;
        let old = usize::try_from(old_size).map_err(|_| LogError::OutOfRange)?;
        if new > st.leaves.len() || old > new {
            return Err(LogError::OutOfRange);
        }
        Ok(ConsistencyProof { old_size, new_size, path: consistency_path(old, &st.leaves[..new]) })
    }

    /// The canonical `LogEntry` bytes at indices `from` (inclusive) to `to` (exclusive),
    /// clipped to the size of the log and to [`MAX_ENTRIES`], read from `log.dat`. A `from`
    /// at or beyond the size, or a `to` below `from`, is [`LogError::OutOfRange`].
    pub fn entries(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, LogError> {
        let st = self.state.lock().expect("lock");
        let size = st.leaves.len() as u64;
        if from >= size || to < from {
            return Err(LogError::OutOfRange);
        }
        let end = to.min(size).min(from + MAX_ENTRIES as u64);
        let bytes = std::fs::read(st.dir.join("log.dat")).map_err(|e| LogError::Unavailable(e.to_string()))?;
        let cut = || LogError::Unavailable("the log file is shorter than the log".into());
        // Records are `[length][entry][chain hash]`, which `replay` verified on open.
        let mut at = MAGIC.len();
        let mut out = Vec::new();
        for index in 0..end {
            let len = u32::from_be_bytes(bytes.get(at..at + 4).ok_or_else(cut)?.try_into().expect("4 bytes")) as usize;
            if index >= from {
                out.push(bytes.get(at + 4..at + 4 + len).ok_or_else(cut)?.to_vec());
            }
            at += 4 + len + 32;
        }
        Ok(out)
    }

    /// The tree size `checkpoint` commits to, if this log has produced that tree.
    fn size_of(&self, checkpoint: &SignedCheckpoint) -> Result<u64, LogError> {
        let st = self.state.lock().expect("lock");
        let size = usize::try_from(checkpoint.size()).map_err(|_| LogError::OutOfRange)?;
        if checkpoint.origin() != self.origin || size > st.leaves.len() || &root(&st.leaves[..size]) != checkpoint.root() {
            return Err(LogError::OutOfRange);
        }
        Ok(checkpoint.size())
    }
}

impl TransparencyLog for FileLogStore {
    fn append(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError> {
        self.append_entry(entry)
    }

    fn checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        Ok(self.latest_checkpoint())
    }

    fn prove_inclusion(&self, leaf_index: u64, checkpoint: &SignedCheckpoint) -> Result<InclusionProof, LogError> {
        let size = self.size_of(checkpoint)?;
        self.inclusion_at(leaf_index, size)
    }

    fn prove_consistency(&self, old_size: u64, checkpoint: &SignedCheckpoint) -> Result<ConsistencyProof, LogError> {
        let size = self.size_of(checkpoint)?;
        self.consistency_between(old_size, size)
    }
}

/// Replaces `dir/head` atomically and durably.
fn write_head(dir: &Path, note: &[u8]) -> Result<(), StoreError> {
    let tmp = dir.join("head.tmp");
    let mut f = File::create(&tmp).map_err(io)?;
    f.write_all(note).and_then(|()| f.sync_all()).map_err(io)?;
    std::fs::rename(&tmp, dir.join("head")).map_err(io)?;
    sync_dir(dir)
}

/// The stored head, verified against `key` and `origin`.
fn read_head(dir: &Path, origin: &str, key: &SigningKey) -> Result<Option<SignedCheckpoint>, StoreError> {
    let note = match std::fs::read(dir.join("head")) {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    };
    let head = SignedCheckpoint::parse(&note).map_err(|e| corrupt(format!("head: {e}")))?;
    let pin = LogPin { origin: origin.into(), public_key: key.public_key().as_bytes().to_vec(), format: CHECKPOINT_FORMAT.into() };
    head.verify(&[pin], 0).map_err(|e| corrupt(format!("the stored head does not verify under this log's key and origin: {e}")))?;
    Ok(Some(head))
}

/// Reads and verifies every record. Returns the leaf hashes, the final chain hash and the
/// length of the good prefix. `signed` is how many entries a signed head covers: a bad
/// record inside that range is corruption, never a torn tail.
fn replay(data: &mut File, signed: u64) -> Result<(Vec<Digest>, Digest, u64), StoreError> {
    let mut bytes = Vec::new();
    data.seek(SeekFrom::Start(0)).map_err(io)?;
    data.read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() < MAGIC.len() {
        if !MAGIC.starts_with(&bytes) || signed > 0 {
            return Err(corrupt("not a log file"));
        }
        // A new file, or a crash while writing the magic.
        data.set_len(0).map_err(io)?;
        data.seek(SeekFrom::Start(0)).map_err(io)?;
        data.write_all(MAGIC).and_then(|()| data.sync_all()).map_err(io)?;
        return Ok((Vec::new(), Digest::from([0; 32]), MAGIC.len() as u64));
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(corrupt("not a log file"));
    }
    let mut at = MAGIC.len();
    let mut prev = Digest::from([0; 32]);
    let mut leaves = Vec::new();
    while at < bytes.len() {
        let covered = (leaves.len() as u64) < signed;
        let torn = |covered: bool, why: &str| if covered { Err(corrupt(why.to_owned())) } else { Ok(()) };
        let Some(len_bytes) = bytes.get(at..at + 4) else {
            torn(covered, "record cut short")?;
            break;
        };
        let len = u32::from_be_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
        if len > MAX_RECORD {
            // A garbage length cannot be a torn write of ours unless it is the final bytes.
            if covered || bytes.len() - at > 4 + MAX_RECORD + 32 {
                return Err(corrupt("record length out of range"));
            }
            break;
        }
        let end = at + 4 + len + 32;
        if end > bytes.len() {
            torn(covered, "record cut short")?;
            break;
        }
        let entry_bytes = &bytes[at + 4..at + 4 + len];
        let next = chain(&prev, entry_bytes);
        if next.as_bytes() != &bytes[at + 4 + len..end] {
            // Only the last record can be a torn write.
            if covered || end != bytes.len() {
                return Err(corrupt(format!("record {} fails its chain hash", leaves.len())));
            }
            break;
        }
        let entry = LogEntry::decode(entry_bytes).map_err(|e| corrupt(format!("record {}: {e}", leaves.len())))?;
        if entry.encode() != entry_bytes {
            return Err(corrupt(format!("record {} is not canonical", leaves.len())));
        }
        leaves.push(leaf_hash(&LeafFormat::Fieldseal.leaf(&entry)));
        prev = next;
        at = end;
    }
    Ok((leaves, prev, at as u64))
}
