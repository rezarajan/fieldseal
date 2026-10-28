//! `CreateTenancy`, `OpenSession`, `LockSession` (COL-001–COL-002, COL-020–COL-027,
//! PLAT-043–PLAT-045).

use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{ContentAddress, Digest, TenancyHandle, TenancyId};
use fieldseal_kernel::local_record::{LocalEntry, SessionKey, derive_session_key};
use fieldseal_policy::domain::{Controls, EffectivePolicy, LockTrigger, RuntimeEvaluator};
use fieldseal_trust::domain::{DeviceKeyKind, KeyProtection};

use super::{CollectionError, CollectionEvent, Runtime, Session, names};
use crate::domain::meta::TenancyMeta;
use crate::domain::pin::PinAttempts;
use crate::domain::ticks::TickState;
use crate::domain::{HashParams, Restriction, RestrictionState, RuntimePin, TenancyState, posture_findings};

const PIN_CHECK: &[u8] = b"fieldseal.dev/pin-check/v1";
/// The `seq` the PIN check entry is encrypted under: no record ever takes it.
pub(crate) const RESERVED_SEQ: u64 = u64::MAX;

/// What opening a session found.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SessionInfo {
    /// Required device restrictions not in force, as `(restriction, state)` (PLAT-043).
    /// They never block the session (PLAT-044).
    pub posture: Vec<(String, String)>,
    /// The device clock is outside the tenancy window: warn only (COL-083).
    pub outside_window: bool,
    /// Whether a bundle is held.
    pub bundle_held: bool,
}

/// The runtime policy defaults, before any bundle carried one.
pub(crate) fn default_policy() -> RuntimeEvaluator {
    let effective = EffectivePolicy { sources: vec![ContentAddress::from([0; 32])], controls: Controls::defaults() };
    RuntimeEvaluator::from_effective(&effective).expect("the policy defaults meet the invariant floors")
}

pub(crate) fn hash_params(policy: &RuntimeEvaluator) -> HashParams {
    let a = policy.policy().pin.argon2;
    HashParams {
        memory_kib: u32::try_from(a.memory.as_bytes() / 1024).unwrap_or(u32::MAX),
        iterations: u32::try_from(a.iterations).unwrap_or(u32::MAX),
        parallelism: u32::try_from(a.parallelism).unwrap_or(u32::MAX),
    }
}

fn restriction_of(name: &str) -> Option<Restriction> {
    Restriction::ALL.into_iter().find(|r| r.name() == name)
}

fn state_name(s: RestrictionState) -> &'static str {
    match s {
        RestrictionState::InForce => "in-force",
        RestrictionState::Missing => "missing",
        RestrictionState::Unknown => "unknown",
    }
}

impl Runtime<'_> {
    /// `CreateTenancy` (COL-001, COL-002): creates the signing, agreement and
    /// session-wrapping keys in the key store with attestation evidence, derives the tenancy
    /// ID, sets the runtime PIN, seals the journal's `open` record, and opens a session.
    /// Works without a network.
    pub fn create_tenancy(&mut self, pin: &RuntimePin) -> Result<SessionInfo, CollectionError> {
        if self.meta.as_ref().is_some_and(|m| matches!(m.state, TenancyState::Local | TenancyState::Registered | TenancyState::Closing)) {
            return Err(CollectionError::TenancyExists);
        }
        let policy = default_policy();
        if !policy.pin_length_acceptable(pin.digits().len() as u64) {
            return Err(CollectionError::PinTooShort(policy.policy().pin.min_length));
        }
        let argon = hash_params(&policy);
        let protection = KeyProtection { unlocked_required: true };
        let challenge = fieldseal_kernel::id::Nonce::from(self.random::<32>());
        let unsupported = |e: fieldseal_trust::ports::KeyStoreError| CollectionError::PlatformUnsupported(format!("key store: {e}"));
        let (sign, sign_pub) = self.p.keys.generate(DeviceKeyKind::Signing, protection, Some(challenge)).map_err(unsupported)?;
        let (agree, agree_pub) = self.p.keys.generate(DeviceKeyKind::Agreement, protection, Some(challenge)).map_err(unsupported)?;
        let (wrap, _) = self.p.keys.generate(DeviceKeyKind::Wrapping, protection, None).map_err(unsupported)?;
        let (Some(sign_pub), Some(agree_pub)) = (sign_pub, agree_pub) else {
            return Err(CollectionError::PlatformUnsupported("key store returned no public key".into()));
        };
        let mut evidence = Vec::new();
        for k in [&sign, &agree] {
            let e = self.p.attestor.evidence(k).map_err(|e| CollectionError::PlatformUnsupported(format!("attestation: {e}")))?;
            evidence.push(sha256(&e.data));
        }
        let tenancy = TenancyId::from(*sha256(sign_pub.as_bytes()).as_bytes());
        let secret = zeroize::Zeroizing::new(self.random::<32>());
        let wrapped_secret = self.p.keys.wrap(&wrap, &secret[..])?;
        let pin_salt = self.random::<16>();
        let pin_hash = zeroize::Zeroizing::new(
            self.p.hash.hash(pin, &pin_salt, argon).ok_or_else(|| CollectionError::PlatformUnsupported("PIN hash parameters".into()))?,
        );
        let key = derive_session_key(&secret[..], &pin_hash, &tenancy);
        let pin_check = LocalEntry::seal(&key, &tenancy, RESERVED_SEQ, self.random::<12>(), PIN_CHECK).encode();
        let record_key = self.prov.provisional_record_key;
        let pin = &policy.policy().pin;
        let meta = TenancyMeta {
            state: TenancyState::Local,
            tenancy,
            sign,
            agree,
            wrap,
            sign_pub,
            agree_pub,
            evidence,
            wrapped_secret,
            pin_salt,
            pin_check,
            build_anchor: self.prov.build_anchor,
            record_key,
            period: fieldseal_kernel::digest::key_id(&record_key),
            handle: TenancyHandle::from(self.random::<16>()),
            certificate: None,
            window: None,
            head: None,
            anchors: vec![self.prov.build_anchor],
            pending_anchors: Vec::new(),
            cleared: Vec::new(),
            received: None,
            saved: None,
            handed_over: None,
            journal_deleted_through: None,
            instruments: Vec::new(),
            policy: None,
            encryptions: 1,
            posture: Vec::new(),
            argon,
            failures_before_lockout: pin.failures_before_lockout,
            lockout_steps_ms: pin.lockout_steps.iter().map(|d| d.as_secs() * 1000).collect(),
        };
        self.meta = Some(meta);
        self.ticks = Some(TickState::new(self.prov.build_anchor, self.now()));
        self.save_meta()?;
        self.p.storage.write(names::DEVICE, &names::pin_attempts(), &self.wrap_attempts(&PinAttempts::default())?)?;
        self.events.push(CollectionEvent::TenancyCreated(tenancy));
        let info = self.start_session(key, policy)?;
        self.seal_open()?;
        Ok(info)
    }

    fn wrap_attempts(&self, a: &PinAttempts) -> Result<Vec<u8>, CollectionError> {
        Ok(self.p.keys.wrap(&self.meta()?.wrap, &a.encode())?)
    }

    pub(crate) fn read_attempts(&self) -> Result<PinAttempts, CollectionError> {
        let meta = self.meta()?;
        let Some(bytes) = self.p.storage.read(names::DEVICE, &names::pin_attempts())? else {
            return Ok(PinAttempts::default());
        };
        // The counter is integrity-protected by the hardware wrapping key (COL-023): a
        // counter that fails to unwrap was tampered with and counts as at the lockout.
        match self.p.keys.unwrap(&meta.wrap, &bytes) {
            Ok(plain) => PinAttempts::decode(&plain).map_err(Into::into),
            Err(fieldseal_trust::ports::KeyStoreError::Unwrap) => {
                let failures = meta.failures_before_lockout.max(1);
                Ok(PinAttempts { failures, wait_ms: meta.lockout_delay_ms(failures).unwrap_or(0), wait_from: Some(self.now()) })
            }
            Err(e) => Err(e.into()),
        }
    }

    fn write_attempts(&self, a: &PinAttempts) -> Result<(), CollectionError> {
        self.p.storage.write(names::DEVICE, &names::pin_attempts(), &self.wrap_attempts(a)?)?;
        Ok(())
    }

    /// Derives the session key a PIN gives, without counting anything.
    fn derive_key(&self, pin: &RuntimePin) -> Result<SessionKey, CollectionError> {
        let meta = self.meta()?;
        let pin_hash = zeroize::Zeroizing::new(
            self.p.hash.hash(pin, &meta.pin_salt, meta.argon).ok_or_else(|| CollectionError::PlatformUnsupported("PIN hash parameters".into()))?,
        );
        let secret = zeroize::Zeroizing::new(self.p.keys.unwrap(&meta.wrap, &meta.wrapped_secret).map_err(|e| match e {
            fieldseal_trust::ports::KeyStoreError::Locked => CollectionError::NotAllowed("unlock the device first".into()),
            e => e.into(),
        })?);
        Ok(derive_session_key(&secret, &pin_hash, &meta.tenancy))
    }

    /// Checks a PIN, counting a failure toward lockout (COL-023, COL-101). Returns the key
    /// for a correct PIN.
    pub(crate) fn check_pin(&mut self, pin: &RuntimePin) -> Result<SessionKey, CollectionError> {
        let now = self.now();
        let mut attempts = self.read_attempts()?;
        if let Some(wait) = attempts.remaining(now) {
            self.write_attempts(&attempts)?;
            return Err(CollectionError::LockedOut(wait.div_ceil(1000)));
        }
        let key = self.derive_key(pin)?;
        let meta = self.meta()?;
        let check = LocalEntry::decode(&meta.pin_check)?;
        let ok = check.open(&key, &meta.tenancy).is_ok_and(|p| p[..] == *PIN_CHECK);
        if ok {
            if attempts.failures > 0 {
                attempts.succeed();
                self.write_attempts(&attempts)?;
            }
            return Ok(key);
        }
        self.count_failure()?;
        let wait = self.read_attempts()?.wait_ms.div_ceil(1000);
        Err(CollectionError::WrongPin(wait))
    }

    /// Counts one failed PIN confirmation toward lockout.
    pub(crate) fn count_failure(&mut self) -> Result<(), CollectionError> {
        let now = self.now();
        let mut attempts = self.read_attempts()?;
        let meta = self.meta()?.clone();
        attempts.fail(now, |f| meta.lockout_delay_ms(f));
        self.write_attempts(&attempts)?;
        if attempts.wait_ms > 0 {
            self.events.push(CollectionEvent::PinLockedOut(attempts.wait_ms.div_ceil(1000)));
        }
        Ok(())
    }

    /// `OpenSession` (COL-022, COL-023): checks the PIN, derives the session key, protects
    /// the windows (PLAT-045), compares device restrictions with policy (PLAT-043), opens the
    /// held bundle, and chains any anchors seen while locked.
    pub fn open_session(&mut self, pin: &RuntimePin) -> Result<SessionInfo, CollectionError> {
        let state = self.meta()?.state;
        if matches!(state, TenancyState::Closed | TenancyState::Erased) {
            return Err(CollectionError::WrongState(state));
        }
        self.lock("reopened");
        let key = self.check_pin(pin)?;
        let info = self.start_session(key, default_policy())?;
        self.resume_after_unlock()?;
        Ok(info)
    }

    fn start_session(&mut self, key: SessionKey, policy: RuntimeEvaluator) -> Result<SessionInfo, CollectionError> {
        for w in self.prov.windows {
            self.p.display.protect(w).map_err(|e| CollectionError::PlatformUnsupported(format!("secure display: {e}")))?;
        }
        self.session = Some(Session {
            key,
            last_activity: self.now(),
            policy,
            held: None,
            languages: Vec::new(),
            window_class: fieldseal_instrument::domain::WindowClass::Compact,
        });
        let bundle_held = self.load_held_bundle()?;
        let posture = self.posture_check()?;
        let outside_window = match (self.meta()?.window, self.p.wall.now_ms()) {
            (Some((nb, na)), Some(now)) => now < nb || now > na,
            _ => false,
        };
        self.events.push(CollectionEvent::SessionOpened);
        Ok(SessionInfo { posture, outside_window, bundle_held })
    }

    /// Re-reads device restrictions and records each required one not in force as a
    /// posture finding (PLAT-043). Findings never block (PLAT-044).
    pub fn posture_check(&mut self) -> Result<Vec<(String, String)>, CollectionError> {
        let policy = &self.session.as_ref().ok_or(CollectionError::Locked)?.policy;
        let required: Vec<Restriction> =
            policy.policy().device.required_restrictions.iter().filter_map(|r| restriction_of(r.as_str())).collect();
        let effective = self.p.device.effective_restrictions();
        let findings: Vec<(String, String)> =
            posture_findings(&required, &effective).into_iter().map(|f| (f.restriction.name().to_owned(), state_name(f.state).to_owned())).collect();
        if let Some(meta) = self.meta.as_mut() {
            meta.posture = findings.clone();
        }
        self.save_meta()?;
        Ok(findings)
    }

    /// `LockSession` (COL-024): drops the session key, the held bundle's decrypted
    /// contents (rosters and names) and any capture in progress from memory.
    pub fn lock(&mut self, reason: &'static str) {
        if self.session.take().is_some() {
            self.capture = None;
            self.events.push(CollectionEvent::SessionLocked(reason));
        }
    }

    /// Locks when policy says the trigger locks (COL-024).
    pub fn on_lock_trigger(&mut self, trigger: LockTrigger) {
        if self.session.as_ref().is_some_and(|s| s.policy.locks_on(trigger)) {
            self.lock(match trigger {
                LockTrigger::Background => "background",
                LockTrigger::ScreenOff => "screen-off",
            });
        }
    }

    /// Requires an open session, locking first if it has been idle longer than policy
    /// allows or the device rebooted (COL-024). Marks activity.
    pub(crate) fn active(&mut self) -> Result<&mut Session, CollectionError> {
        let now = self.now();
        let expired = match &self.session {
            None => return Err(CollectionError::Locked),
            Some(s) => {
                s.last_activity.boot_count != now.boot_count
                    || s.policy.session_expired(fieldseal_policy::domain::Duration::from_secs(
                        now.elapsed_ms.saturating_sub(s.last_activity.elapsed_ms) / 1000,
                    ))
            }
        };
        if expired {
            self.lock("idle");
            return Err(CollectionError::Locked);
        }
        let s = self.session.as_mut().expect("checked above");
        s.last_activity = now;
        Ok(s)
    }

    /// Sets the collector's instrument languages, most preferred first (PLAT-051). A capture
    /// in progress switches at once, keeping every value.
    pub fn set_languages(&mut self, languages: &[&str]) -> Result<(), CollectionError> {
        let s = self.active()?;
        s.languages = languages.iter().map(|l| (*l).to_owned()).collect();
        self.relanguage_capture()
    }

    /// Sets the device's window class (INS-207). A capture in progress keeps its layout:
    /// layouts switch only between records (COL-108).
    pub fn set_window_class(&mut self, class: fieldseal_instrument::domain::WindowClass) -> Result<(), CollectionError> {
        self.active()?.window_class = class;
        Ok(())
    }

    /// The forgotten-PIN explanation (COL-027).
    pub fn forgotten_pin_help() -> &'static str {
        "The authority can close this tenancy (reason forgotten-pin). Sealed work is not lost: it stays on the device until it is delivered."
    }

    pub(crate) fn build_anchor(&self) -> Result<Digest, CollectionError> {
        Ok(self.meta()?.build_anchor)
    }
}
