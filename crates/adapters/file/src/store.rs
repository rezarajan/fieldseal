//! A file-backed [`RegistryStore`] for development: the in-memory store plus an append-only
//! journal of every change, replayed at start-up, so tokens, accounts, tenancies, devices,
//! nonces and access tokens survive a restart.
//!
//! The journal is `registry.journal` in the state directory: records of a 4-byte big-endian
//! length and a payload (an operation code and its arguments, see [`crate::codec`]). A
//! truncated tail (a crash mid-write) is ignored. The store is single-writer: one factory
//! process owns the directory; other processes read it with [`FileRegistryStore::snapshot`].
//!
//! **Not for production**: no encryption at rest, no compaction, no multi-process locking.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fieldseal_adapters_memory::registration::MemoryRegistryStore;
use fieldseal_kernel::id::{Nonce, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::{AccessToken, Account, AccountId, DeviceId, IssuedToken, RegisteredDevice, TenancyRecord, TokenSecret};
use fieldseal_registration::ports::{IssuedNonce, RegistryStore, RegistryStoreError, TokenError};

use crate::codec::{self as c, R, W};

/// The journal's file name.
pub const JOURNAL: &str = "registry.journal";

const PUT_TOKEN: u8 = 1;
const CONSUME: u8 = 2;
const PUT_ACCOUNT: u8 = 3;
const PUT_TENANCY: u8 = 4;
const PUT_DEVICE: u8 = 5;
const PUT_NONCE: u8 = 6;
const TAKE_NONCE: u8 = 7;
const RECORD_JTI: u8 = 8;
const PUT_ACCESS: u8 = 9;

fn apply(inner: &MemoryRegistryStore, payload: &[u8]) -> c::Res<()> {
    let mut r = R(payload);
    // Replayed operations that the store refuses today (an expired consumption, a duplicate)
    // were refused or harmless when they were first journaled; they are ignored.
    match r.u8()? {
        PUT_TOKEN => {
            let _ = inner.put_token(&c::get_issued(&mut r)?);
        }
        CONSUME => {
            let (s, now) = (c::get_secret(&mut r)?, c::get_time(&mut r)?);
            let _ = inner.consume_token(&s, now);
        }
        PUT_ACCOUNT => {
            let _ = inner.put_account(&c::get_account(&mut r)?);
        }
        PUT_TENANCY => {
            let _ = inner.put_tenancy(&c::get_tenancy(&mut r)?);
        }
        PUT_DEVICE => {
            let _ = inner.put_device(&c::get_device(&mut r)?);
        }
        PUT_NONCE => {
            let _ = inner.put_nonce(&c::get_nonce(&mut r)?);
        }
        TAKE_NONCE => {
            let (n, t, now) = (c::get_nonce_value(&mut r)?, c::get_tid(&mut r)?, c::get_time(&mut r)?);
            let _ = inner.take_nonce(&n, &t, now);
        }
        RECORD_JTI => {
            let (t, j, until, now) = (c::get_tid(&mut r)?, c::get_jti(&mut r)?, c::get_time(&mut r)?, c::get_time(&mut r)?);
            let _ = inner.record_jti(&t, &j, until, now);
        }
        PUT_ACCESS => {
            let _ = inner.put_access_token(&c::get_access(&mut r)?);
        }
        other => return Err(format!("unknown journal operation {other}")),
    }
    Ok(())
}

fn replay(path: &Path, inner: &MemoryRegistryStore) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    let mut rest = bytes.as_slice();
    while rest.len() >= 4 {
        let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if rest.len() < 4 + n {
            break; // a truncated tail
        }
        apply(inner, &rest[4..4 + n]).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        rest = &rest[4 + n..];
    }
    Ok(())
}

/// The journaled registry store.
pub struct FileRegistryStore {
    inner: MemoryRegistryStore,
    journal: Mutex<File>,
    path: PathBuf,
}

impl FileRegistryStore {
    /// Opens (creating if needed) the state directory and replays its journal.
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
        let path = dir.as_ref().join(JOURNAL);
        let inner = MemoryRegistryStore::new();
        replay(&path, &inner)?;
        let journal = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { inner, journal: Mutex::new(journal), path })
    }

    /// A read-only copy of the state in `dir` (an empty store if there is none yet), for
    /// another process to consult.
    pub fn snapshot(dir: impl AsRef<Path>) -> std::io::Result<MemoryRegistryStore> {
        let inner = MemoryRegistryStore::new();
        replay(&dir.as_ref().join(JOURNAL), &inner)?;
        Ok(inner)
    }

    /// The journal file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `op` on the inner store and journals `entry` if it succeeded, under one lock so
    /// the journal order is the order the store applied the changes.
    fn journaled<T, E>(&self, entry: impl FnOnce(&mut W), op: impl FnOnce(&MemoryRegistryStore) -> Result<T, E>, keep: impl Fn(&T) -> bool) -> Result<T, E> {
        let mut file = self.journal.lock().expect("lock");
        let out = op(&self.inner)?;
        if keep(&out) {
            let mut w = W::default();
            entry(&mut w);
            let mut framed = (w.0.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&w.0);
            // A failed write cannot be reported through the port's error types without
            // undoing the change; the development stack stops loudly instead.
            if let Err(e) = file.write_all(&framed).and_then(|()| file.sync_data()) {
                eprintln!("fieldseal: cannot write {}: {e}", self.path.display());
                std::process::exit(1);
            }
        }
        Ok(out)
    }
}

fn op(code: u8) -> W {
    let mut w = W::default();
    w.0.push(code);
    w
}

macro_rules! entry {
    ($code:expr, |$w:ident| $body:block) => {
        |out: &mut W| {
            let mut $w = op($code);
            $body
            out.0 = $w.0;
        }
    };
}

impl RegistryStore for FileRegistryStore {
    fn put_token(&self, token: &IssuedToken) -> Result<(), RegistryStoreError> {
        self.journaled(entry!(PUT_TOKEN, |w| { c::put_issued(&mut w, token) }), |s| s.put_token(token), |()| true)
    }

    fn token(&self, secret: &TokenSecret) -> Result<Option<(IssuedToken, u32)>, RegistryStoreError> {
        self.inner.token(secret)
    }

    fn consume_token(&self, secret: &TokenSecret, now: AuthorityTime) -> Result<IssuedToken, TokenError> {
        self.journaled(entry!(CONSUME, |w| { c::put_secret(&mut w, secret); w.u64(now.0) }), |s| s.consume_token(secret, now), |_| true)
    }

    fn put_account(&self, account: &Account) -> Result<(), RegistryStoreError> {
        self.journaled(entry!(PUT_ACCOUNT, |w| { c::put_account(&mut w, account) }), |s| s.put_account(account), |()| true)
    }

    fn account(&self, id: &AccountId) -> Result<Option<Account>, RegistryStoreError> {
        self.inner.account(id)
    }

    fn put_tenancy(&self, tenancy: &TenancyRecord) -> Result<(), RegistryStoreError> {
        self.journaled(entry!(PUT_TENANCY, |w| { c::put_tenancy(&mut w, tenancy) }), |s| s.put_tenancy(tenancy), |()| true)
    }

    fn tenancy(&self, id: &TenancyId) -> Result<Option<TenancyRecord>, RegistryStoreError> {
        self.inner.tenancy(id)
    }

    fn tenancy_by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyRecord>, RegistryStoreError> {
        self.inner.tenancy_by_handle(handle)
    }

    fn tenancies_of(&self, account: &AccountId) -> Result<Vec<TenancyRecord>, RegistryStoreError> {
        self.inner.tenancies_of(account)
    }

    fn put_device(&self, device: &RegisteredDevice) -> Result<(), RegistryStoreError> {
        self.journaled(entry!(PUT_DEVICE, |w| { c::put_device(&mut w, device) }), |s| s.put_device(device), |()| true)
    }

    fn device(&self, id: &DeviceId) -> Result<Option<RegisteredDevice>, RegistryStoreError> {
        self.inner.device(id)
    }

    fn devices_of(&self, account: &AccountId) -> Result<Vec<RegisteredDevice>, RegistryStoreError> {
        self.inner.devices_of(account)
    }

    fn put_nonce(&self, nonce: &IssuedNonce) -> Result<(), RegistryStoreError> {
        self.journaled(entry!(PUT_NONCE, |w| { c::put_nonce(&mut w, nonce) }), |s| s.put_nonce(nonce), |()| true)
    }

    fn take_nonce(&self, nonce: &Nonce, tenancy: &TenancyId, now: AuthorityTime) -> Result<bool, RegistryStoreError> {
        self.journaled(
            entry!(TAKE_NONCE, |w| { w.bytes(nonce.as_bytes()); c::put_tid(&mut w, tenancy); w.u64(now.0) }),
            |s| s.take_nonce(nonce, tenancy, now),
            |_| true,
        )
    }

    fn record_jti(&self, tenancy: &TenancyId, jti: &[u8; 16], until: AuthorityTime, now: AuthorityTime) -> Result<bool, RegistryStoreError> {
        self.journaled(
            entry!(RECORD_JTI, |w| { c::put_tid(&mut w, tenancy); w.bytes(jti); w.u64(until.0); w.u64(now.0) }),
            |s| s.record_jti(tenancy, jti, until, now),
            |recorded| *recorded,
        )
    }

    fn put_access_token(&self, token: &AccessToken) -> Result<(), RegistryStoreError> {
        self.journaled(entry!(PUT_ACCESS, |w| { c::put_access(&mut w, token) }), |s| s.put_access_token(token), |()| true)
    }

    fn access_token(&self, value: &[u8; 32]) -> Result<Option<AccessToken>, RegistryStoreError> {
        self.inner.access_token(value)
    }
}
