//! In-memory adapters for the Registration context's driven ports.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_kernel::crypto::{P256PublicKey, Purpose, Signature};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{CollectionPeriodId, Digest, Nonce, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::seal::{RecipientKey, RecipientSecret, SealedBox, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::auth::phishing_resistant_from_claims;
use fieldseal_registration::domain::wire::{PopToken, PostureBody, RequestBody, TokenRefusal, factory_sealing_key};
use fieldseal_registration::domain::{
    AccessToken, Account, AccountId, AuthenticatedPerson, AuthenticationMethods, DeviceId, IssuedToken, KeyEvidence,
    ManagementMode, MethodAssurance, NonceSource, RegisteredDevice, RegistrationToken, ReportedRestriction, Role, RollProof,
    TenancyRecord, TokenSecret,
};
use fieldseal_trust::application::{Authority, SOFTWARE_EVIDENCE_FORMAT};
use fieldseal_trust::domain::{
    AttestationEvidence, BundleVersion, Ceremony, CollectionPeriod, DeviceKeyKind, IssueTerms, KeyAlgorithm, KeyCertificate,
    KeyRole, RecordKeyTerms, Retention, RuntimeBuild, Threshold, TrustBundle, TrustBundleContents,
};
use fieldseal_trust::ports::{KeyCustody, RandomSource, SourceRng};

use crate::trust::{MemoryKeyCustody, toy_digest};
use fieldseal_registration::ports::{
    FleetRegistry, IdentityError, IdentityProvider, IssuedNonce, Notifier, NotifierError, PendingSignIn, PortalEvent,
    ProgressError, ReceivedProgress, RegistryStore, RegistryStoreError, SignInStart, TokenError,
};

struct TokenEntry {
    token: IssuedToken,
    used: u32,
}

#[derive(Default)]
struct RegistryState {
    tokens: BTreeMap<TokenSecret, TokenEntry>,
    accounts: BTreeMap<AccountId, Account>,
    tenancies: BTreeMap<TenancyId, TenancyRecord>,
    devices: BTreeMap<DeviceId, RegisteredDevice>,
    nonces: BTreeMap<Nonce, IssuedNonce>,
    jtis: BTreeMap<(TenancyId, [u8; 16]), AuthorityTime>,
    access: BTreeMap<[u8; 32], AccessToken>,
}

/// In-memory [`RegistryStore`]. One mutex guards all state, so token, nonce and `jti`
/// consumption is atomic.
#[derive(Default)]
pub struct MemoryRegistryStore {
    state: Mutex<RegistryState>,
}

impl MemoryRegistryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl RegistryStore for MemoryRegistryStore {
    fn put_token(&self, token: &IssuedToken) -> Result<(), RegistryStoreError> {
        let mut state = self.state.lock().expect("lock");
        if state.tokens.contains_key(&token.token.secret) {
            return Err(RegistryStoreError::DuplicateToken);
        }
        state.tokens.insert(token.token.secret, TokenEntry { token: token.clone(), used: 0 });
        Ok(())
    }

    fn token(&self, secret: &TokenSecret) -> Result<Option<(IssuedToken, u32)>, RegistryStoreError> {
        let state = self.state.lock().expect("lock");
        Ok(state.tokens.get(secret).map(|e| (e.token.clone(), e.token.max_uses.saturating_sub(e.used))))
    }

    fn consume_token(&self, secret: &TokenSecret, now: AuthorityTime) -> Result<IssuedToken, TokenError> {
        let mut state = self.state.lock().expect("lock");
        let entry = state.tokens.get_mut(secret).ok_or(TokenError::Unknown)?;
        if entry.used >= entry.token.max_uses {
            return Err(TokenError::Used);
        }
        if now > entry.token.expires_at {
            return Err(TokenError::Expired);
        }
        entry.used += 1;
        Ok(entry.token.clone())
    }

    fn put_account(&self, account: &Account) -> Result<(), RegistryStoreError> {
        self.state.lock().expect("lock").accounts.insert(account.id.clone(), account.clone());
        Ok(())
    }

    fn account(&self, id: &AccountId) -> Result<Option<Account>, RegistryStoreError> {
        Ok(self.state.lock().expect("lock").accounts.get(id).cloned())
    }

    fn put_tenancy(&self, tenancy: &TenancyRecord) -> Result<(), RegistryStoreError> {
        let mut state = self.state.lock().expect("lock");
        if let Some(existing) = state.tenancies.get(&tenancy.id)
            && !existing.keeps_key_history(tenancy)
        {
            return Err(RegistryStoreError::HistoryViolation);
        }
        state.tenancies.insert(tenancy.id, tenancy.clone());
        Ok(())
    }

    fn tenancy(&self, id: &TenancyId) -> Result<Option<TenancyRecord>, RegistryStoreError> {
        Ok(self.state.lock().expect("lock").tenancies.get(id).cloned())
    }

    fn tenancy_by_handle(&self, handle: &TenancyHandle) -> Result<Option<TenancyRecord>, RegistryStoreError> {
        Ok(self.state.lock().expect("lock").tenancies.values().find(|t| t.handle == *handle).cloned())
    }

    fn tenancies_of(&self, account: &AccountId) -> Result<Vec<TenancyRecord>, RegistryStoreError> {
        Ok(self.state.lock().expect("lock").tenancies.values().filter(|t| t.account == *account).cloned().collect())
    }

    fn put_device(&self, device: &RegisteredDevice) -> Result<(), RegistryStoreError> {
        self.state.lock().expect("lock").devices.insert(device.id.clone(), device.clone());
        Ok(())
    }

    fn device(&self, id: &DeviceId) -> Result<Option<RegisteredDevice>, RegistryStoreError> {
        Ok(self.state.lock().expect("lock").devices.get(id).cloned())
    }

    fn devices_of(&self, account: &AccountId) -> Result<Vec<RegisteredDevice>, RegistryStoreError> {
        Ok(self.state.lock().expect("lock").devices.values().filter(|d| d.account == *account).cloned().collect())
    }

    fn put_nonce(&self, nonce: &IssuedNonce) -> Result<(), RegistryStoreError> {
        self.state.lock().expect("lock").nonces.insert(nonce.nonce, nonce.clone());
        Ok(())
    }

    fn take_nonce(&self, nonce: &Nonce, tenancy: &TenancyId, now: AuthorityTime) -> Result<bool, RegistryStoreError> {
        let mut state = self.state.lock().expect("lock");
        match state.nonces.get(nonce) {
            Some(n) if n.tenancy == *tenancy => {
                let live = now <= n.expires_at;
                state.nonces.remove(nonce);
                Ok(live)
            }
            _ => Ok(false),
        }
    }

    fn record_jti(
        &self,
        tenancy: &TenancyId,
        jti: &[u8; 16],
        until: AuthorityTime,
        now: AuthorityTime,
    ) -> Result<bool, RegistryStoreError> {
        let mut state = self.state.lock().expect("lock");
        state.jtis.retain(|_, lapse| *lapse >= now);
        let key = (*tenancy, *jti);
        if state.jtis.contains_key(&key) {
            return Ok(false);
        }
        state.jtis.insert(key, until);
        Ok(true)
    }

    fn put_access_token(&self, token: &AccessToken) -> Result<(), RegistryStoreError> {
        self.state.lock().expect("lock").access.insert(token.value, token.clone());
        Ok(())
    }

    fn access_token(&self, value: &[u8; 32]) -> Result<Option<AccessToken>, RegistryStoreError> {
        Ok(self.state.lock().expect("lock").access.get(value).cloned())
    }
}

struct DevPerson {
    account: AccountId,
    roles: Vec<String>,
    methods: Vec<String>,
    assurance: MethodAssurance,
}

/// In-memory [`IdentityProvider`] for tests and local development. A sign-in "redirects"
/// straight back to the portal with `code` set to the default person's login name (or
/// none); finishing looks the code up. **Not an identity provider**: the methods it
/// reports are whatever it was configured with, so a factory must never use it in
/// production.
#[derive(Default)]
pub struct MemoryIdentityProvider {
    people: Mutex<BTreeMap<String, DevPerson>>,
    default_login: Mutex<Option<String>>,
    counter: AtomicU64,
}

impl MemoryIdentityProvider {
    /// No known people.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a person who signs in as `login`, with provider role names (`collector`,
    /// `operator`, or any other name) and the `amr` values the "provider" reports.
    pub fn add(&self, login: &str, account: &str, roles: &[&str], methods: &[&str], assurance: MethodAssurance) {
        self.people.lock().expect("lock").insert(
            login.to_owned(),
            DevPerson {
                account: AccountId(account.into()),
                roles: roles.iter().map(|r| (*r).to_owned()).collect(),
                methods: methods.iter().map(|m| (*m).to_owned()).collect(),
                assurance,
            },
        );
    }

    /// Makes every sign-in come back as `login`.
    pub fn set_default(&self, login: Option<&str>) {
        *self.default_login.lock().expect("lock") = login.map(str::to_owned);
    }

    /// The person signed in as `login`.
    pub fn person(&self, login: &str) -> Option<AuthenticatedPerson> {
        self.people.lock().expect("lock").get(login).map(|p| AuthenticatedPerson {
            account: p.account.clone(),
            roles: p.roles.iter().filter_map(|r| Role::parse(r)).collect(),
            role_names: p.roles.clone(),
            authentication: AuthenticationMethods {
                phishing_resistant: phishing_resistant_from_claims(&p.methods, None),
                methods: p.methods.clone(),
                assurance: p.assurance,
            },
        })
    }
}

impl IdentityProvider for MemoryIdentityProvider {
    fn start_sign_in(&self, redirect_uri: &str) -> Result<SignInStart, IdentityError> {
        let state = format!("s{}", self.counter.fetch_add(1, Ordering::SeqCst));
        let login = self.default_login.lock().expect("lock").clone().unwrap_or_default();
        let sep = if redirect_uri.contains('?') { '&' } else { '?' };
        Ok(SignInStart {
            redirect_to: format!("{redirect_uri}{sep}state={state}&code={login}"),
            pending: PendingSignIn { state: state.clone(), secret: state.into_bytes() },
        })
    }

    fn finish_sign_in(
        &self,
        pending: &PendingSignIn,
        callback: &BTreeMap<String, String>,
    ) -> Result<AuthenticatedPerson, IdentityError> {
        let state = callback.get("state").ok_or_else(|| IdentityError::NotAuthenticated("no state".into()))?;
        if *state != pending.state || pending.secret != state.as_bytes() {
            return Err(IdentityError::NotAuthenticated("state does not match".into()));
        }
        let code = callback.get("code").ok_or_else(|| IdentityError::NotAuthenticated("no code".into()))?;
        self.person(code).ok_or_else(|| IdentityError::NotAuthenticated("unknown person".into()))
    }
}

/// In-memory [`ReceivedProgress`]: the highest `seq` received per tenancy, as set.
#[derive(Default)]
pub struct MemoryReceivedProgress {
    highest: Mutex<BTreeMap<TenancyId, Seq>>,
}

impl MemoryReceivedProgress {
    /// Nothing received.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that intake has received `seq` from `tenancy`.
    pub fn received(&self, tenancy: TenancyId, seq: Seq) {
        let mut h = self.highest.lock().expect("lock");
        let e = h.entry(tenancy).or_insert(seq);
        if seq > *e {
            *e = seq;
        }
    }
}

impl ReceivedProgress for MemoryReceivedProgress {
    fn highest_received(&self, tenancy: &TenancyId) -> Result<Option<Seq>, ProgressError> {
        Ok(self.highest.lock().expect("lock").get(tenancy).copied())
    }
}

/// In-memory [`FleetRegistry`]: a set of serials.
#[derive(Default)]
pub struct MemoryFleetRegistry {
    serials: Mutex<BTreeSet<String>>,
}

impl MemoryFleetRegistry {
    /// An empty fleet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a serial to the fleet.
    pub fn add(&self, serial: &str) {
        self.serials.lock().expect("lock").insert(serial.to_owned());
    }
}

impl FleetRegistry for MemoryFleetRegistry {
    fn knows(&self, serial: &str) -> bool {
        self.serials.lock().expect("lock").contains(serial)
    }
}

/// In-memory [`Notifier`]: records events; can be told to fail, to prove nothing depends on it.
#[derive(Default)]
pub struct MemoryNotifier {
    events: Mutex<Vec<(AccountId, PortalEvent)>>,
    failing: Mutex<bool>,
}

impl MemoryNotifier {
    /// A notifier that delivers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every later notification fail.
    pub fn set_failing(&self, failing: bool) {
        *self.failing.lock().expect("lock") = failing;
    }

    /// Events delivered so far.
    pub fn delivered(&self) -> Vec<(AccountId, PortalEvent)> {
        self.events.lock().expect("lock").clone()
    }
}

impl Notifier for MemoryNotifier {
    fn notify(&self, account: &AccountId, event: &PortalEvent) -> Result<(), NotifierError> {
        if *self.failing.lock().expect("lock") {
            return Err(NotifierError::Undelivered("set to fail".into()));
        }
        self.events.lock().expect("lock").push((account.clone(), event.clone()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// A development authority and a software device, for tests, the simulator and running a
// factory locally. **Not for production**: keys live in process memory and devices are
// unattested.

/// A one-person authority with a root, the two `registration` keys (P-256 signing,
/// X25519 sealing), a `record` key for one collection period, and a trust bundle listing
/// them. All keys are generated in a [`MemoryKeyCustody`].
pub struct DevAuthority<R: RandomSource> {
    /// The custody holding every key.
    pub custody: MemoryKeyCustody<R>,
    /// The root certificate.
    pub root: KeyCertificate,
    /// The registration signing key's certificate.
    pub signing: KeyCertificate,
    /// The registration sealing key's certificate.
    pub sealing: KeyCertificate,
    /// The collection period's record-key certificate.
    pub record: KeyCertificate,
    /// The trust bundle devices are provisioned with.
    pub bundle: TrustBundle,
}

/// Errors building a [`DevAuthority`].
pub type DevAuthorityError = fieldseal_trust::application::UseCaseError;

/// Creates a development authority valid from `now` for a year, accepting runtime builds
/// with the given app identities (the software verifier reports `fieldseal-simulator`).
pub fn dev_authority<R: RandomSource>(random: R, now: AuthorityTime, app_ids: &[&str]) -> Result<DevAuthority<R>, DevAuthorityError> {
    let custody = MemoryKeyCustody::new(random);
    let year = 364 * AuthorityTime::DAY;
    let ceremony = Ceremony {
        authority: "development".into(),
        threshold: Threshold::new(2, 2)?,
        custodians: vec!["custodian-1".into(), "custodian-2".into()],
        witnesses: vec!["witness".into()],
        held_at: now,
        not_before: now,
        not_after: AuthorityTime(now.0 + 2 * year),
    };
    let authority = Authority::new(&custody, "dev-ceremony");
    let root = authority.init_root(ceremony)?.root;
    let terms = |serial| IssueTerms {
        purpose: Purpose::Registration,
        record: None,
        not_before: now,
        not_after: AuthorityTime(now.0 + year),
        serial,
    };
    let signing_key = custody.generate(KeyRole::Purpose(Purpose::Registration), KeyAlgorithm::P256)?;
    let signing = authority.issue(&root, &authority.request(&signing_key.id, Some(Purpose::Registration))?, terms(1))?;
    let sealing_key = custody.generate(KeyRole::Purpose(Purpose::Registration), KeyAlgorithm::X25519)?;
    let sealing = authority.issue(&root, &authority.request(&sealing_key.id, Some(Purpose::Registration))?, terms(2))?;
    let record_key = custody.generate(KeyRole::Purpose(Purpose::Record), KeyAlgorithm::X25519)?;
    let period = CollectionPeriod::new(
        CollectionPeriodId::new("development").expect("non-empty"),
        now,
        AuthorityTime(now.0 + 180 * AuthorityTime::DAY),
    )?;
    let record = authority.open_collection_period(
        &root,
        &authority.request(&record_key.id, Some(Purpose::Record))?,
        RecordKeyTerms { period, retention: Retention(180 * AuthorityTime::DAY) },
        now,
        3,
    )?;
    let contents = TrustBundleContents {
        name: "development".into(),
        version: BundleVersion::parse("1.0.0")?,
        issued: now,
        roots: vec![root.clone()],
        certificates: vec![signing.clone(), sealing.clone(), record.clone()],
        publishers: BTreeMap::new(),
        attestation_roots: BTreeMap::new(),
        runtime_builds: app_ids
            .iter()
            .map(|a| RuntimeBuild {
                platform: "software".into(),
                app_id: (*a).to_owned(),
                signing_digests: vec![sha256(a.as_bytes())],
            })
            .collect(),
        logs: vec![],
        revocations: vec![],
    };
    let bundle = authority.build_bundle(contents, &[&root], None)?;
    Ok(DevAuthority { custody, root, signing, sealing, record, bundle })
}

/// Software attestation evidence in the format [`crate::trust::SoftwareAttestationVerifier`]
/// verifies: always unattested (TRU-061).
pub fn software_evidence(kind: DeviceKeyKind, unlocked_required: bool, challenge: &Nonce, key: &P256PublicKey) -> AttestationEvidence {
    let code = match kind {
        DeviceKeyKind::Signing => 0u8,
        DeviceKeyKind::Agreement => 1,
        DeviceKeyKind::Wrapping => 2,
    };
    let mut data = vec![code, u8::from(unlocked_required)];
    data.extend_from_slice(challenge.as_bytes());
    data.extend_from_slice(key.as_bytes());
    let check = toy_digest(&[b"evidence", &data]);
    data.extend_from_slice(&check[..8]);
    AttestationEvidence { format: SOFTWARE_EVIDENCE_FORMAT.into(), data }
}

/// A runtime's registration keys held in software: a real P-256 signing key and a real
/// P-256 agreement key, with software evidence. What `fieldseal device simulate` and the
/// tests register; production policy refuses it (REG-017).
pub struct SoftwareDevice {
    sign: SigningKey,
    agree: RecipientSecret,
    /// The runtime build identity it reports.
    pub build: String,
}

impl SoftwareDevice {
    /// Generates keys from `random`.
    pub fn new(random: &dyn RandomSource) -> Self {
        let mut rng = SourceRng(random);
        Self {
            sign: SigningKey::generate(&mut rng),
            agree: RecipientSecret::generate(Suite::Fs1P, &mut rng),
            build: "fieldseal-simulator/0.1.0".into(),
        }
    }

    /// A device with keys that exist already (for example read from a key file): the
    /// signing key and the P-256 agreement secret (suite `fs1-p`).
    pub fn from_keys(sign: SigningKey, agree: RecipientSecret) -> Self {
        Self { sign, agree, build: "fieldseal-simulator/0.1.0".into() }
    }

    /// The signing public key.
    pub fn sign_pub(&self) -> P256PublicKey {
        self.sign.public_key()
    }

    /// The agreement public key.
    pub fn agree_pub(&self) -> P256PublicKey {
        match self.agree.public().expect("valid key") {
            RecipientKey::P256(k) => k,
            RecipientKey::X25519(_) => unreachable!("generated for fs1-p"),
        }
    }

    /// The tenancy this device's keys register.
    pub fn tenancy(&self) -> TenancyId {
        TenancyId::from(*sha256(self.sign_pub().as_bytes()).as_bytes())
    }

    /// Signs a prepared message with the signing key.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.sign.sign_message(message)
    }

    /// The request body for `token`, with software evidence over its nonce (REG-011).
    pub fn body(&self, token: &RegistrationToken, label: Option<&str>) -> RequestBody {
        RequestBody {
            token: token.secret,
            nonce: token.nonce,
            nonce_source: NonceSource::Factory,
            sign_pub: self.sign_pub(),
            agree_pub: self.agree_pub(),
            evidence: vec![
                KeyEvidence { kind: DeviceKeyKind::Signing, evidence: software_evidence(DeviceKeyKind::Signing, true, &token.nonce, &self.sign_pub()) },
                KeyEvidence {
                    kind: DeviceKeyKind::Agreement,
                    evidence: software_evidence(DeviceKeyKind::Agreement, true, &token.nonce, &self.agree_pub()),
                },
            ],
            build: self.build.clone(),
            prev_closing: None,
            label: label.map(str::to_owned),
        }
    }

    /// Seals `body` with this device's proof of possession, to the factory key in `bundle`;
    /// with `roll`, also signed by `current`, the device's current keys (REG-060).
    pub fn seal(
        &self,
        random: &dyn RandomSource,
        bundle: &TrustBundle,
        at: AuthorityTime,
        body: &RequestBody,
        roll: Option<(&SoftwareDevice, TenancyId)>,
    ) -> SealedBox {
        let factory = factory_sealing_key(bundle, at).expect("the trust bundle certifies a registration sealing key");
        let pop = self.sign_message(&body.pop_message());
        let roll = roll.map(|(current, tenancy)| RollProof { tenancy, signature: current.sign_message(&body.pop_message()) });
        body.seal(&mut SourceRng(random), &factory, &pop, roll.as_ref()).expect("sealable")
    }

    /// A complete request for `token`: checks the token against `bundle` first (REG-010).
    pub fn request(
        &self,
        random: &dyn RandomSource,
        bundle: &TrustBundle,
        token: &RegistrationToken,
        label: Option<&str>,
    ) -> Result<SealedBox, TokenRefusal> {
        token.verify(bundle)?;
        Ok(self.seal(random, bundle, token.issued_at, &self.body(token, label), None))
    }

    /// A PoP token for one API request (WIRE-170).
    pub fn pop_token(&self, tenancy: TenancyId, method: &str, url: &str, iat: AuthorityTime, jti: [u8; 16], ath: Option<Digest>) -> PopToken {
        let mut t = PopToken { tenancy, method: method.into(), url: url.into(), iat, jti, ath, signature: Signature(vec![]) };
        t.signature = self.sign_message(&t.message());
        t
    }

    /// A posture report answering `nonce`, with no fresh evidence.
    pub fn posture(&self, tenancy: TenancyId, nonce: Nonce, restrictions: &[(&str, ReportedRestriction)]) -> Vec<u8> {
        let body = PostureBody {
            tenancy,
            nonce,
            mode: ManagementMode::SelfManaged,
            restrictions: restrictions.iter().map(|(n, s)| ((*n).to_owned(), *s)).collect(),
            evidence: None,
        };
        body.encode_report(&self.sign_message(&body.pop_message()))
    }
}
