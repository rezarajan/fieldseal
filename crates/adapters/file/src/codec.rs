//! A small length-prefixed binary codec for the registry's records, used by the journal.
//! Private to this adapter: the format is not a wire format and may change between versions
//! of the development stack.

use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::{CohortId, Generation, KeyId, Nonce, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::wire::TenancyCertificate;
use fieldseal_registration::domain::{
    AccessToken, Account, AccountId, AuthRecord, CohortAssignment, DeviceId, FingerprintWords,
    IssuedToken, KeyState, NonceSource, RegisteredDevice, RegisteredKey, RegistrationToken,
    ReportedProfile, ReportedVersion, Role, TenancyRecord, TenancyState, TokenSecret, Window,
};
use fieldseal_registration::ports::IssuedNonce;
use fieldseal_trust::domain::{AttestationClaims, AttestationEvidence, BootState, DeviceKeyKind, SecurityLevel};

/// A decoding failure.
pub type Res<T> = Result<T, String>;

/// Writes fields.
#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    /// A `u64`.
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bool(&mut self, v: bool) {
        self.u8(u8::from(v));
    }
    /// Bytes with a length prefix.
    pub fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
    fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
    fn opt<T>(&mut self, v: &Option<T>, f: impl FnOnce(&mut Self, &T)) {
        match v {
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
            None => self.u8(0),
        }
    }
    fn list<T>(&mut self, v: &[T], f: impl Fn(&mut Self, &T)) {
        self.u32(v.len() as u32);
        for x in v {
            f(self, x);
        }
    }
}

/// Reads fields.
pub struct R<'a>(pub &'a [u8]);

impl R<'_> {
    fn take(&mut self, n: usize) -> Res<&[u8]> {
        if self.0.len() < n {
            return Err("truncated record".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    /// A `u8`.
    pub fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| "u32")?))
    }
    /// A `u64`.
    pub fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| "u64")?))
    }
    fn bool(&mut self) -> Res<bool> {
        Ok(self.u8()? != 0)
    }
    /// Length-prefixed bytes.
    pub fn bytes(&mut self) -> Res<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn arr<const N: usize>(&mut self) -> Res<[u8; N]> {
        self.bytes()?.try_into().map_err(|_| format!("expected {N} bytes"))
    }
    fn str(&mut self) -> Res<String> {
        String::from_utf8(self.bytes()?).map_err(|_| "not UTF-8".into())
    }
    fn opt<T>(&mut self, f: impl FnOnce(&mut Self) -> Res<T>) -> Res<Option<T>> {
        Ok(if self.u8()? == 1 { Some(f(self)?) } else { None })
    }
    fn list<T>(&mut self, f: impl Fn(&mut Self) -> Res<T>) -> Res<Vec<T>> {
        let n = self.u32()? as usize;
        (0..n).map(|_| f(self)).collect()
    }
    /// Whether everything was read.
    pub fn done(&self) -> bool {
        self.0.is_empty()
    }
}

fn time(r: &mut R<'_>) -> Res<AuthorityTime> {
    Ok(AuthorityTime(r.u64()?))
}

// ---- small types -------------------------------------------------------------------------------

fn put_auth(w: &mut W, a: &AuthRecord) {
    w.list(&a.methods, |w, m| w.str(m));
    w.bool(a.phishing_resistant);
    w.bool(a.asserted);
}

fn get_auth(r: &mut R<'_>) -> Res<AuthRecord> {
    Ok(AuthRecord { methods: r.list(R::str)?, phishing_resistant: r.bool()?, asserted: r.bool()? })
}

fn put_window(w: &mut W, v: &Window) {
    w.u64(v.not_before.0);
    w.u64(v.not_after.0);
    w.u64(v.grace_ms);
}

fn get_window(r: &mut R<'_>) -> Res<Window> {
    Ok(Window { not_before: time(r)?, not_after: time(r)?, grace_ms: r.u64()? })
}

fn put_words(w: &mut W, v: &FingerprintWords) {
    for i in v.indices() {
        w.u32(u32::from(i));
    }
}

fn get_words(r: &mut R<'_>) -> Res<FingerprintWords> {
    let mut idx = [0u16; 4];
    for i in &mut idx {
        *i = u16::try_from(r.u32()?).map_err(|_| "word index")?;
    }
    FingerprintWords::from_indices(idx).map_err(|e| e.to_string())
}

fn put_cohort(w: &mut W, c: &CohortAssignment) {
    w.str(c.cohort.as_str());
    w.u32(c.generation.0);
}

fn get_cohort(r: &mut R<'_>) -> Res<CohortAssignment> {
    Ok(CohortAssignment { cohort: CohortId::new(r.str()?).map_err(|_| "empty cohort")?, generation: Generation(r.u32()?) })
}

fn kind_code(k: DeviceKeyKind) -> u8 {
    match k {
        DeviceKeyKind::Signing => 0,
        DeviceKeyKind::Agreement => 1,
        DeviceKeyKind::Wrapping => 2,
    }
}

fn kind_of(c: u8) -> Res<DeviceKeyKind> {
    Ok(match c {
        0 => DeviceKeyKind::Signing,
        1 => DeviceKeyKind::Agreement,
        2 => DeviceKeyKind::Wrapping,
        _ => return Err("key kind".into()),
    })
}

fn put_claims(w: &mut W, c: &AttestationClaims) {
    w.u8(match c.security_level {
        SecurityLevel::Software => 0,
        SecurityLevel::Tee => 1,
        SecurityLevel::Tpm => 2,
        SecurityLevel::SecureElement => 3,
        SecurityLevel::StrongBox => 4,
    });
    w.bool(c.origin_generated);
    w.u8(kind_code(c.kind));
    // Device-only claims are absent when the verifier did not establish them (TRU-063, TRU-118).
    w.opt(&c.unlocked_required, |w, b| w.bool(*b));
    w.bytes(c.challenge.as_bytes());
    w.opt(&c.app_id, |w, s| w.str(s));
    w.opt(&c.app_version, |w, s| w.str(s));
    w.opt(&c.os_patch_level, |w, s| w.str(s));
    w.opt(&c.boot_state, |w, b| {
        w.u8(match b {
            BootState::Verified => 0,
            BootState::SelfSigned => 1,
            BootState::Unverified => 2,
        })
    });
    w.opt(&c.bootloader_locked, |w, b| w.bool(*b));
    w.opt(&c.device_serial, |w, s| w.str(s));
}

fn get_claims(r: &mut R<'_>) -> Res<AttestationClaims> {
    Ok(AttestationClaims {
        security_level: match r.u8()? {
            0 => SecurityLevel::Software,
            1 => SecurityLevel::Tee,
            2 => SecurityLevel::Tpm,
            3 => SecurityLevel::SecureElement,
            4 => SecurityLevel::StrongBox,
            _ => return Err("security level".into()),
        },
        origin_generated: r.bool()?,
        kind: kind_of(r.u8()?)?,
        unlocked_required: r.opt(R::bool)?,
        challenge: Nonce::from(r.arr::<32>()?),
        app_id: r.opt(R::str)?,
        app_version: r.opt(R::str)?,
        os_patch_level: r.opt(R::str)?,
        boot_state: r.opt(|r| match r.u8()? {
            0 => Ok(BootState::Verified),
            1 => Ok(BootState::SelfSigned),
            2 => Ok(BootState::Unverified),
            _ => Err("boot state".into()),
        })?,
        bootloader_locked: r.opt(R::bool)?,
        device_serial: r.opt(R::str)?,
    })
}

fn put_profile(w: &mut W, p: &ReportedProfile) {
    w.str(&p.instrument_schema.to_string());
    w.opt(&p.catalogue_reference, |w, c| w.str(c));
}

/// Reads a reported profile, refusing a version or catalogue text the wire would refuse.
fn get_profile(r: &mut R<'_>) -> Res<ReportedProfile> {
    let schema = r.str()?;
    Ok(ReportedProfile {
        instrument_schema: ReportedVersion::parse(&schema).ok_or("profile schema version")?,
        catalogue_reference: r.opt(|r| {
            let c = r.str()?;
            if ReportedProfile::catalogue_ok(&c) {
                Ok(c)
            } else {
                Err("profile catalogue version".into())
            }
        })?,
    })
}

fn put_key(w: &mut W, k: &RegisteredKey) {
    w.u32(k.index);
    w.u8(kind_code(k.kind));
    w.bytes(k.public_key.as_bytes());
    w.str(&k.evidence.format);
    w.bytes(&k.evidence.data);
    w.opt(&k.claims, put_claims);
    w.u8(match k.state {
        KeyState::Active => 0,
        KeyState::Rolled => 1,
        KeyState::Revoked => 2,
    });
}

fn get_key(r: &mut R<'_>) -> Res<RegisteredKey> {
    Ok(RegisteredKey {
        index: r.u32()?,
        kind: kind_of(r.u8()?)?,
        public_key: P256PublicKey::from_bytes(&r.bytes()?).map_err(|e| e.to_string())?,
        evidence: AttestationEvidence { format: r.str()?, data: r.bytes()? },
        claims: r.opt(get_claims)?,
        state: match r.u8()? {
            0 => KeyState::Active,
            1 => KeyState::Rolled,
            2 => KeyState::Revoked,
            _ => return Err("key state".into()),
        },
    })
}

const STATES: [TenancyState; 9] = [
    TenancyState::Pending,
    TenancyState::Held,
    TenancyState::Rejected,
    TenancyState::Registered,
    TenancyState::Flagged,
    TenancyState::Lost,
    TenancyState::Closing,
    TenancyState::Closed,
    TenancyState::Retired,
];

// ---- records -----------------------------------------------------------------------------------

/// Writes an issued token.
pub fn put_issued(w: &mut W, t: &IssuedToken) {
    w.bytes(&t.token.encode().unwrap_or_default());
    w.str(&t.account.0);
    w.u64(t.expires_at.0);
    w.u32(t.max_uses);
    put_auth(w, &t.authentication);
}

/// Reads an issued token.
pub fn get_issued(r: &mut R<'_>) -> Res<IssuedToken> {
    Ok(IssuedToken {
        token: RegistrationToken::decode(&r.bytes()?).map_err(|e| e.to_string())?,
        account: AccountId(r.str()?),
        expires_at: time(r)?,
        max_uses: r.u32()?,
        authentication: get_auth(r)?,
    })
}

/// Writes an account.
pub fn put_account(w: &mut W, a: &Account) {
    w.str(&a.id.0);
    w.bytes(&a.collector);
    w.list(&a.roles, |w, r| w.u8(if *r == Role::Collector { 0 } else { 1 }));
}

/// Reads an account.
pub fn get_account(r: &mut R<'_>) -> Res<Account> {
    Ok(Account {
        id: AccountId(r.str()?),
        collector: r.arr::<16>()?,
        roles: r.list(|r| Ok(if r.u8()? == 0 { Role::Collector } else { Role::Operator }))?,
    })
}

/// Writes a tenancy.
pub fn put_tenancy(w: &mut W, t: &TenancyRecord) {
    w.bytes(t.id.as_bytes());
    w.bytes(t.handle.as_bytes());
    w.str(&t.account.0);
    w.str(&t.device.0);
    w.u8(STATES.iter().position(|s| *s == t.state).unwrap_or(0) as u8);
    w.list(&t.keys, put_key);
    put_window(w, &t.window);
    w.bytes(t.record_key.as_bytes());
    w.list(&t.cohorts, put_cohort);
    w.opt(&t.cutoff, |w, s| w.u64(s.0));
    put_words(w, &t.words);
    w.bytes(t.token.as_bytes());
    w.bool(t.batch);
    w.u64(t.pending_until.0);
    w.u8(if t.nonce_source == NonceSource::Factory { 0 } else { 1 });
    w.str(&t.build);
    put_profile(w, &t.profile);
    put_auth(w, &t.authentication);
    w.list(&t.reasons, |w, s| w.str(s));
    w.opt(&t.certificate, |w, c| w.bytes(&c.encode()));
    w.opt(&t.last_seen, |w, s| w.u64(s.0));
}

/// Reads a tenancy.
pub fn get_tenancy(r: &mut R<'_>) -> Res<TenancyRecord> {
    Ok(TenancyRecord {
        id: TenancyId::from(r.arr::<32>()?),
        handle: TenancyHandle::from(r.arr::<16>()?),
        account: AccountId(r.str()?),
        device: DeviceId(r.str()?),
        state: *STATES.get(r.u8()? as usize).ok_or("tenancy state")?,
        keys: r.list(get_key)?,
        window: get_window(r)?,
        record_key: KeyId::from(r.arr::<16>()?),
        cohorts: r.list(get_cohort)?,
        cutoff: r.opt(|r| Ok(Seq(r.u64()?)))?,
        words: get_words(r)?,
        token: TokenSecret::from_bytes(r.arr::<16>()?),
        batch: r.bool()?,
        pending_until: time(r)?,
        nonce_source: if r.u8()? == 0 { NonceSource::Factory } else { NonceSource::Device },
        build: r.str()?,
        profile: get_profile(r)?,
        authentication: get_auth(r)?,
        reasons: r.list(R::str)?,
        certificate: r.opt(|r| TenancyCertificate::decode(&r.bytes()?).map_err(|e| e.to_string()))?,
        last_seen: r.opt(|r| Ok(AuthorityTime(r.u64()?)))?,
    })
}

/// Writes a device.
pub fn put_device(w: &mut W, d: &RegisteredDevice) {
    w.str(&d.id.0);
    w.str(&d.account.0);
    w.str(&d.nickname);
    put_words(w, &d.words);
    w.opt(&d.hardware_id, |w, s| w.str(s));
    w.list(&d.tenancies, |w, t| w.bytes(t.as_bytes()));
}

/// Reads a device.
pub fn get_device(r: &mut R<'_>) -> Res<RegisteredDevice> {
    Ok(RegisteredDevice {
        id: DeviceId(r.str()?),
        account: AccountId(r.str()?),
        nickname: r.str()?,
        words: get_words(r)?,
        hardware_id: r.opt(R::str)?,
        tenancies: r.list(|r| Ok(TenancyId::from(r.arr::<32>()?)))?,
    })
}

/// Writes a nonce.
pub fn put_nonce(w: &mut W, n: &IssuedNonce) {
    w.bytes(n.nonce.as_bytes());
    w.bytes(n.tenancy.as_bytes());
    w.u64(n.expires_at.0);
}

/// Reads a nonce.
pub fn get_nonce(r: &mut R<'_>) -> Res<IssuedNonce> {
    Ok(IssuedNonce { nonce: Nonce::from(r.arr::<32>()?), tenancy: TenancyId::from(r.arr::<32>()?), expires_at: time(r)? })
}

/// Writes an access token.
pub fn put_access(w: &mut W, a: &AccessToken) {
    w.bytes(&a.value);
    w.bytes(a.tenancy.as_bytes());
    w.bytes(a.key.as_bytes());
    w.u64(a.expires_at.0);
}

/// Reads an access token.
pub fn get_access(r: &mut R<'_>) -> Res<AccessToken> {
    Ok(AccessToken { value: r.arr::<32>()?, tenancy: TenancyId::from(r.arr::<32>()?), key: KeyId::from(r.arr::<16>()?), expires_at: time(r)? })
}

/// Reads a `TokenSecret`.
pub fn get_secret(r: &mut R<'_>) -> Res<TokenSecret> {
    Ok(TokenSecret::from_bytes(r.arr::<16>()?))
}

/// Writes a `TokenSecret`.
pub fn put_secret(w: &mut W, s: &TokenSecret) {
    w.bytes(s.as_bytes());
}

/// Reads a tenancy ID.
pub fn get_tid(r: &mut R<'_>) -> Res<TenancyId> {
    Ok(TenancyId::from(r.arr::<32>()?))
}

/// Writes a tenancy ID.
pub fn put_tid(w: &mut W, t: &TenancyId) {
    w.bytes(t.as_bytes());
}

/// Reads a nonce value.
pub fn get_nonce_value(r: &mut R<'_>) -> Res<Nonce> {
    Ok(Nonce::from(r.arr::<32>()?))
}

/// Reads a 16-byte array.
pub fn get_jti(r: &mut R<'_>) -> Res<[u8; 16]> {
    r.arr::<16>()
}

/// Reads a time.
pub fn get_time(r: &mut R<'_>) -> Res<AuthorityTime> {
    time(r)
}
