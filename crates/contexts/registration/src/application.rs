//! Use cases: the driving ports the Registration context offers
//! (`docs/reference/spec/registration.md` §3), as methods of [`Factory`].
//!
//! Nothing here reads a clock, draws randomness or performs I/O: time comes from the
//! `AuthorityClock` port, randomness from `RandomSource`, keys stay in `KeyCustody`, and
//! state lives in `RegistryStore` (ADR 0028). The factory process itself is stateless
//! (twelve-factor VI).

use std::collections::BTreeSet;

use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{Digest, KeyId, Nonce, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::seal::{RecipientKey, SealedBox};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, WireError};
use fieldseal_policy::domain::{
    Decision, DecisionPoint, DecisionRecord, EffectivePolicy, Facts, Subject, UnknownRestriction, Verdict, facts_digest,
};
use fieldseal_policy::ports::{DecisionLog, PolicyEngine};
use fieldseal_trust::application::VerifyEvidence;
use fieldseal_trust::domain::{
    AttestationClaims, AuthorityPublicKey, BootState, DeviceKeyKind, KeyRole, SecurityLevel, TrustBundle,
};
use fieldseal_trust::ports::{AttestationVerifier, AuthorityClock, KeyCustody, RandomSource};

use crate::domain::auth::{AuthRefusal, check_authentication};
use crate::domain::checks::{UnattestedKeys, attestation_findings};
use crate::domain::wire::{
    CertifiedKey, CloseCertificate, PopToken, TenancyCertificate, decode_posture, decode_request, root_fingerprint,
    verify_pop,
};
use crate::domain::{
    AccessToken, Account, AccountId, AuthenticatedPerson, CloseReason, DeviceId, FingerprintWords, IssuedToken,
    KeyState, NonceSource, RegisteredDevice, RegisteredKey, RegistrationRequest, RegistrationRoute, RegistrationToken,
    Role, TenancyRecord, TenancyState, TenancyTerms, TokenSecret, policy_address,
};
use crate::ports::{
    FleetRegistry, IssuedNonce, Notifier, PortalEvent, ReceivedProgress, RegistryStore, RegistryStoreError, TokenError,
};

/// How far a PoP token's `iat` may be from the factory's clock (WIRE-171).
pub const POP_WINDOW_MS: u64 = 300 * AuthorityTime::SECOND;

/// The caller name the factory logs custody uses under (no personal data, REG §7 logs).
const CALLER: &str = "factory-registration";

/// Why a registration use case failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    /// Policy refused the operation, with its reasons (REG-031).
    #[error("policy denied: {}", .0.join(", "))]
    PolicyDenied(Vec<String>),
    /// The account has reached its device limit (REG-042).
    #[error("device limit reached")]
    DeviceLimitReached,
    /// The sign-in isn't strong enough (REG-002, REG-002a).
    #[error(transparent)]
    Authentication(#[from] AuthRefusal),
    /// The person lacks the role the operation needs.
    #[error("not authorised: {0}")]
    NotAuthorised(&'static str),
    /// The token couldn't be used (REG-005, REG-006).
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The request came by a route the token doesn't allow (REG-053).
    #[error("request arrived by the wrong route for its token")]
    RouteMismatch,
    /// The token, tenancy or device belongs to another account (REG-021, REG-053).
    #[error("belongs to another account")]
    WrongAccount,
    /// The request's nonce isn't the token's, or a posture nonce wasn't issued.
    #[error("nonce mismatch")]
    NonceMismatch,
    /// The proof of possession didn't verify (REG-014 step 2).
    #[error("proof of possession invalid")]
    ProofInvalid,
    /// The attestation evidence didn't verify (REG-014 step 3).
    #[error("attestation evidence rejected: {0}")]
    EvidenceRejected(String),
    /// The request couldn't be opened or decoded.
    #[error("malformed: {0}")]
    Malformed(WireError),
    /// A PoP token's `jti` was seen before (WIRE-171).
    #[error("replayed proof-of-possession token")]
    Replay,
    /// The tenancy isn't pending (REG-021).
    #[error("tenancy is not pending")]
    NotPending,
    /// The tenancy isn't held.
    #[error("tenancy is not held")]
    NotHeld,
    /// The pending request lapsed unconfirmed (REG-022).
    #[error("the request was not confirmed in time")]
    ConfirmationExpired,
    /// The tenancy isn't registered (`GetCertificate`, `IssueApiToken`).
    #[error("tenancy is not registered")]
    NotRegistered,
    /// The tenancy has been revoked (lost, closed or retired).
    #[error("tenancy is revoked")]
    Revoked,
    /// No such tenancy or device.
    #[error("not found")]
    NotFound,
    /// A different request already registered this tenancy ID.
    #[error("tenancy already exists")]
    TenancyExists,
    /// A port failed.
    #[error("{0}")]
    Port(String),
}

impl From<RegistryStoreError> for RegistrationError {
    fn from(e: RegistryStoreError) -> Self {
        Self::Port(e.to_string())
    }
}

/// The factory's own settings, from its deployment (twelve-factor III).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FactoryConfig {
    /// The factory URL written into tokens (WIRE-121).
    pub factory_url: String,
    /// The `registration` P-256 key in custody that signs tokens and certificates.
    pub signing_key: KeyId,
    /// The `registration` X25519 key in custody that opens requests.
    pub sealing_key: KeyId,
    /// What new tenancies are registered for.
    pub terms: TenancyTerms,
    /// Whether unattested keys may register (non-production only, REG-017).
    pub unattested: UnattestedKeys,
    /// How long a posture nonce lasts, in milliseconds.
    pub posture_nonce_ttl_ms: u64,
    /// How long an access token lasts, in milliseconds (REG-070: short-lived).
    pub access_token_ttl_ms: u64,
}

/// The driven ports a [`Factory`] uses.
pub struct FactoryPorts<'a> {
    /// Accounts, tokens and tenancies.
    pub store: &'a dyn RegistryStore,
    /// The registration keys.
    pub custody: &'a dyn KeyCustody,
    /// One verifier per accepted evidence format.
    pub verifiers: Vec<&'a dyn AttestationVerifier>,
    /// Policy evaluation.
    pub engine: &'a dyn PolicyEngine,
    /// Where every decision is logged (POL-040).
    pub log: &'a dyn DecisionLog,
    /// The factory's clock.
    pub clock: &'a dyn AuthorityClock,
    /// Secrets, nonces and handles.
    pub random: &'a dyn RandomSource,
    /// What intake has received, for cutoffs.
    pub progress: &'a dyn ReceivedProgress,
    /// The fleet registry, if the deployment has one (REG-016).
    pub fleet: Option<&'a dyn FleetRegistry>,
    /// The portal's notifier, if any. Never relied on.
    pub notifier: Option<&'a dyn Notifier>,
}

/// How a request reached the factory (REG-053).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Submission {
    /// Sent by the runtime itself.
    Online,
    /// Uploaded at the portal by a signed-in account (the air-gapped file route).
    Upload(AccountId),
}

/// A request accepted as `pending` (or a key roll applied).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Submitted {
    /// The tenancy.
    pub tenancy: TenancyRecord,
    /// The words both sides show.
    pub words: FingerprintWords,
}

/// The result of a posture re-check (REG-081).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PostureOutcome {
    /// Whether the report was clean.
    pub ok: bool,
    /// Why it was flagged.
    pub reasons: Vec<String>,
}

/// A device in an account's list (REG-043), with its latest tenancy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceView {
    /// The device.
    pub device: RegisteredDevice,
    /// Its latest tenancy.
    pub tenancy: Option<TenancyRecord>,
}

/// The Registration use cases over their ports, for one effective policy and trust bundle.
pub struct Factory<'a> {
    ports: FactoryPorts<'a>,
    bundle: &'a TrustBundle,
    policy: &'a EffectivePolicy,
    config: &'a FactoryConfig,
    trust_root: Digest,
    sealing_public: RecipientKey,
}

fn hex8(id: &[u8]) -> String {
    lower_hex(&id[..8])
}

impl<'a> Factory<'a> {
    /// Wires the use cases. Checks that the signing key is a `registration` key certified
    /// in `bundle` (so devices can verify tokens, REG-010) and that the sealing key is an
    /// X25519 `registration` key in custody.
    pub fn new(
        ports: FactoryPorts<'a>,
        bundle: &'a TrustBundle,
        policy: &'a EffectivePolicy,
        config: &'a FactoryConfig,
    ) -> Result<Self, RegistrationError> {
        let role = KeyRole::Purpose(Purpose::Registration);
        let cert = bundle
            .certificates_for(&config.signing_key)
            .find(|c| c.role() == role)
            .ok_or_else(|| RegistrationError::Port("the registration signing key is not certified in the trust bundle".into()))?;
        let root = bundle
            .root(cert.issuer())
            .ok_or_else(|| RegistrationError::Port("the registration key's issuer is not a root of the trust bundle".into()))?;
        let trust_root = root_fingerprint(root.public_key().encoded());
        let sealing = ports.custody.public_key(&config.sealing_key).map_err(|e| RegistrationError::Port(e.to_string()))?;
        let sealing_public = match (sealing.role, sealing.public_key) {
            (r, AuthorityPublicKey::X25519(k)) if r == role => {
                RecipientKey::x25519(&k).map_err(|_| RegistrationError::Port("the sealing key is a small-order X25519 point".into()))?
            }
            _ => return Err(RegistrationError::Port("the sealing key is not an X25519 registration key".into())),
        };
        Ok(Self { ports, bundle, policy, config, trust_root, sealing_public })
    }

    /// The key devices seal requests to (WIRE-134).
    pub fn sealing_key(&self) -> &RecipientKey {
        &self.sealing_public
    }

    /// The trust bundle the factory verifies against.
    pub fn bundle(&self) -> &TrustBundle {
        self.bundle
    }

    /// The effective factory policy.
    pub fn policy(&self) -> &EffectivePolicy {
        self.policy
    }

    /// The factory's settings.
    pub fn config(&self) -> &FactoryConfig {
        self.config
    }

    /// The factory's clock.
    pub fn now(&self) -> AuthorityTime {
        self.ports.clock.now()
    }

    fn random<const N: usize>(&self) -> [u8; N] {
        let mut b = [0u8; N];
        self.ports.random.fill(&mut b);
        b
    }

    fn decide(&self, point: DecisionPoint, facts: Facts, subject: Subject) -> Decision {
        let decision = self.ports.engine.evaluate(point, self.policy, &facts).unwrap_or_else(|e| Decision {
            point,
            verdict: point.failure_verdict(),
            reasons: vec![format!("policy-engine-failure: {e}")],
            obligations: vec![],
            policy: self.policy.sources.clone(),
        });
        let record = DecisionRecord {
            decision: decision.clone(),
            input_digest: facts_digest(point, &facts),
            subject,
            at: self.now(),
            resolves: None,
        };
        // POL-040: a decision that can't be logged is not made; refuse rather than proceed.
        match self.ports.log.append(&record) {
            Ok(_) => decision,
            Err(e) => Decision { verdict: Verdict::Deny, reasons: vec![format!("decision-log-unavailable: {e}")], ..decision },
        }
    }

    fn notify(&self, account: &AccountId, event: PortalEvent) {
        if let Some(n) = self.ports.notifier {
            // Never relied on (REG §4 Notifier).
            let _ = n.notify(account, &event);
        }
    }

    fn sign(&self, tag: &fieldseal_kernel::crypto::DomainTag, structure: &Value) -> Result<fieldseal_kernel::crypto::Signature, RegistrationError> {
        self.ports
            .custody
            .sign(&self.config.signing_key, KeyRole::Purpose(Purpose::Registration), tag, structure, CALLER)
            .map_err(|e| RegistrationError::Port(e.to_string()))
    }

    fn tenancy(&self, id: &TenancyId) -> Result<TenancyRecord, RegistrationError> {
        self.ports.store.tenancy(id)?.ok_or(RegistrationError::NotFound)
    }

    /// Distinct devices of `account` with a tenancy that counts towards the limit, other
    /// than `except`.
    fn active_devices(&self, account: &AccountId, except: Option<&DeviceId>) -> Result<u64, RegistrationError> {
        let devices: BTreeSet<DeviceId> = self
            .ports
            .store
            .tenancies_of(account)?
            .into_iter()
            .filter(|t| t.state.is_active() && !t.batch && Some(&t.device) != except)
            .map(|t| t.device)
            .collect();
        Ok(devices.len() as u64)
    }

    fn check_device_limit(&self, account: &AccountId, except: Option<&DeviceId>, subject: Subject) -> Result<(), RegistrationError> {
        let active = self.active_devices(account, except)?;
        let facts = Facts::from([("activeDevices".to_owned(), Value::Int(i128::from(active)))]);
        let d = self.decide(DecisionPoint::DeviceAdd, facts, subject);
        if d.verdict == Verdict::Allow { Ok(()) } else { Err(RegistrationError::DeviceLimitReached) }
    }

    // -----------------------------------------------------------------------------------
    // IssueToken (REG-002..007, REG-041..044).

    /// `IssueToken`: a signed-in collector or operator asks for a token for `uses` devices
    /// (more than one only for an operator's batch token, REG-044).
    pub fn issue_token(
        &self,
        person: &AuthenticatedPerson,
        route: RegistrationRoute,
        uses: u32,
    ) -> Result<IssuedToken, RegistrationError> {
        let reg = self.policy.factory().registration;
        let authentication = check_authentication(&reg, &person.authentication)?;
        if !person.has(Role::Collector) && !person.has(Role::Operator) {
            return Err(RegistrationError::NotAuthorised("a collector or operator role is needed"));
        }
        if uses == 0 {
            return Err(RegistrationError::PolicyDenied(vec!["no-uses".into()]));
        }
        let batch = uses > 1;
        if batch {
            if !person.has(Role::Operator) {
                return Err(RegistrationError::PolicyDenied(vec!["batch-tokens-not-for-collectors".into()]));
            }
            if u64::from(uses) > reg.batch_tokens.max_uses {
                return Err(RegistrationError::PolicyDenied(vec!["batch-exceeds-max-uses".into()]));
            }
        }
        let ttl = if batch {
            reg.batch_tokens.ttl
        } else if route == RegistrationRoute::AirGapped {
            reg.air_gapped_token_ttl
        } else {
            reg.token_ttl
        };
        let subject = Subject::Registration(format!("token-for:{}", hex8(sha256(person.account.0.as_bytes()).as_bytes())));
        let role = person
            .role_names
            .iter()
            .find(|n| reg.batch_tokens.roles.contains(n))
            .cloned()
            .unwrap_or_else(|| if person.has(Role::Operator) { Role::Operator } else { Role::Collector }.as_str().to_owned());
        let facts = Facts::from([
            ("batch".to_owned(), Value::Bool(batch)),
            ("airGapped".to_owned(), Value::Bool(route == RegistrationRoute::AirGapped)),
            ("requestedTtlSeconds".to_owned(), Value::Int(i128::from(ttl.as_secs()))),
            ("role".to_owned(), Value::Text(role)),
            ("phishingResistantAuth".to_owned(), Value::Bool(authentication.phishing_resistant)),
        ]);
        let d = self.decide(DecisionPoint::RegistrationTokenIssue, facts, subject.clone());
        if !matches!(d.verdict, Verdict::Allow | Verdict::Flag) {
            return Err(RegistrationError::PolicyDenied(d.reasons));
        }
        if !batch {
            self.check_device_limit(&person.account, None, subject)?;
        }

        let now = self.now();
        let account = match self.ports.store.account(&person.account)? {
            Some(mut a) => {
                a.roles = person.roles.clone();
                a
            }
            None => Account { id: person.account.clone(), collector: self.random(), roles: person.roles.clone() },
        };
        self.ports.store.put_account(&account)?;

        let mut token = RegistrationToken {
            factory: self.config.factory_url.clone(),
            trust_root: self.trust_root,
            secret: TokenSecret::from_bytes(self.random()),
            nonce: Nonce::from(self.random::<32>()),
            route,
            issued_at: now,
            signer: self.config.signing_key,
            signature: fieldseal_kernel::crypto::Signature(vec![]),
        };
        token.signature = self.sign(&tags::REGISTRATION_TOKEN, &token.signed_structure())?;
        token.encode().map_err(RegistrationError::Malformed)?;
        let issued = IssuedToken {
            token,
            account: person.account.clone(),
            expires_at: now.checked_add(ttl.as_secs() * AuthorityTime::SECOND).unwrap_or(AuthorityTime(u64::MAX)),
            max_uses: uses,
            authentication,
        };
        self.ports.store.put_token(&issued)?;
        Ok(issued)
    }

    // -----------------------------------------------------------------------------------
    // SubmitRequest (REG-010..017, REG-050..053).

    fn open(&self, sealed: &SealedBox) -> Result<RegistrationRequest, RegistrationError> {
        let plaintext = self
            .ports
            .custody
            .open(&self.config.sealing_key, Purpose::Registration, &tags::REGISTRATION_SEAL, sealed, CALLER)
            .map_err(|e| match e {
                fieldseal_trust::ports::CustodyError::Open(w) => RegistrationError::Malformed(w),
                other => RegistrationError::Port(other.to_string()),
            })?;
        decode_request(&plaintext).map_err(RegistrationError::Malformed)
    }

    /// Step 1 without using the token: it exists, has uses left, hasn't expired by the
    /// factory's clock, and arrived by a route its account allows (REG-053).
    fn check_token(&self, secret: &TokenSecret, via: &Submission, now: AuthorityTime) -> Result<IssuedToken, RegistrationError> {
        let (token, remaining) = self.ports.store.token(secret)?.ok_or(TokenError::Unknown)?;
        if remaining == 0 {
            return Err(TokenError::Used.into());
        }
        if now > token.expires_at {
            return Err(TokenError::Expired.into());
        }
        match via {
            Submission::Online if token.token.route == RegistrationRoute::AirGapped => Err(RegistrationError::RouteMismatch),
            Submission::Upload(account) if *account != token.account => Err(RegistrationError::WrongAccount),
            _ => Ok(token),
        }
    }

    /// Step 3: every public key has evidence, and each verifies with the request's nonce as
    /// the challenge. Returns the claims for the signing and agreement keys.
    fn verify_evidence(&self, request: &RegistrationRequest) -> Result<(AttestationClaims, AttestationClaims), RegistrationError> {
        let verify = VerifyEvidence::new(self.ports.verifiers.clone());
        let claims_for = |kind: DeviceKeyKind, key| {
            let e = request
                .evidence
                .iter()
                .find(|e| e.kind == kind)
                .ok_or_else(|| RegistrationError::EvidenceRejected(format!("no evidence for the {kind:?} key")))?;
            verify
                .verify(self.bundle, &e.evidence, &request.nonce, key)
                .map_err(|err| RegistrationError::EvidenceRejected(err.to_string()))
        };
        let sign = claims_for(DeviceKeyKind::Signing, &request.sign_pub)?;
        let agree = claims_for(DeviceKeyKind::Agreement, &request.agree_pub)?;
        Ok((sign, agree))
    }

    fn sufficiency(&self, request: &RegistrationRequest, sign: &AttestationClaims, agree: &AttestationClaims) -> Vec<String> {
        let att = self.policy.factory().attestation;
        let format = |kind| request.evidence.iter().find(|e| e.kind == kind).map(|e| e.evidence.format.clone()).unwrap_or_default();
        let mut reasons = attestation_findings(
            &att,
            self.bundle,
            self.config.unattested,
            &format(DeviceKeyKind::Signing),
            DeviceKeyKind::Signing,
            &request.nonce,
            sign,
        );
        reasons.extend(attestation_findings(
            &att,
            self.bundle,
            self.config.unattested,
            &format(DeviceKeyKind::Agreement),
            DeviceKeyKind::Agreement,
            &request.nonce,
            agree,
        ));
        reasons.sort();
        reasons.dedup();
        reasons
    }

    /// `SubmitRequest`: opens a sealed request (online, or uploaded by the token's account)
    /// and verifies, in order (REG-014): the token, the proof of possession, the
    /// attestation evidence, then policy. The token is consumed once steps 1–3 pass. A
    /// request that passes is `pending` until the same account confirms its words
    /// (REG-021); one that policy denies is kept as `rejected` with its reasons (REG-031).
    /// A key roll (`roll` present) is applied directly (REG-060).
    ///
    /// Retrying the same request returns the existing result (twelve-factor IX).
    pub fn submit(&self, sealed: &SealedBox, via: Submission) -> Result<Submitted, RegistrationError> {
        let request = self.open(sealed)?;
        if request.roll.is_some() {
            return self.roll(&request, &via);
        }
        let words = request.fingerprint_words();
        let existing = self.ports.store.tenancy(&request.tenancy)?;
        if let Some(existing) = &existing
            && existing.token == request.token
            && existing.words == words
        {
            return Ok(Submitted { tenancy: existing.clone(), words });
        }
        let now = self.now();
        // 1. Token.
        let token = self.check_token(&request.token, &via, now)?;
        if request.nonce_source == NonceSource::Factory && request.nonce != token.token.nonce {
            return Err(RegistrationError::NonceMismatch);
        }
        // 2. Proof of possession over the nonce and body.
        verify_pop(&request.sign_pub, &request.nonce, &request.body_digest, &request.proof_of_possession)
            .map_err(|_| RegistrationError::ProofInvalid)?;
        // 3. Attestation evidence.
        let (sign_claims, agree_claims) = self.verify_evidence(&request)?;
        if existing.is_some() {
            return Err(RegistrationError::TenancyExists);
        }
        // The token is used now, atomically (REG-005).
        let token = self.ports.store.consume_token(&request.token, now)?;

        let device = self.device_for(&token.account, &sign_claims, &request)?;
        let mut record = TenancyRecord {
            id: request.tenancy,
            handle: TenancyHandle::from(self.random::<16>()),
            account: token.account.clone(),
            device: device.id.clone(),
            state: TenancyState::Pending,
            keys: vec![
                RegisteredKey {
                    index: 0,
                    kind: DeviceKeyKind::Signing,
                    public_key: request.sign_pub.clone(),
                    evidence: evidence_of(&request, DeviceKeyKind::Signing),
                    claims: Some(sign_claims.clone()),
                    state: KeyState::Active,
                },
                RegisteredKey {
                    index: 0,
                    kind: DeviceKeyKind::Agreement,
                    public_key: request.agree_pub.clone(),
                    evidence: evidence_of(&request, DeviceKeyKind::Agreement),
                    claims: Some(agree_claims.clone()),
                    state: KeyState::Active,
                },
            ],
            window: self.config.terms.window,
            record_key: self.config.terms.record_key,
            cohorts: self.config.terms.cohorts.clone(),
            cutoff: None,
            words,
            token: request.token,
            batch: token.is_batch(),
            pending_until: token.expires_at,
            nonce_source: request.nonce_source,
            build: request.build.clone(),
            profile: request.profile.clone(),
            authentication: token.authentication.clone(),
            reasons: vec![],
            certificate: None,
            last_seen: Some(now),
        };
        // 4. Policy: attestation sufficiency (REG-015, REG-017) denies.
        let reasons = self.sufficiency(&request, &sign_claims, &agree_claims);
        let device_busy = self.has_live_tenancy(&device)?;
        let mut device = device;
        device.words = words;
        device.tenancies.push(record.id);
        if !reasons.is_empty() {
            record.state = TenancyState::Rejected;
            record.reasons = reasons.clone();
            self.ports.store.put_tenancy(&record)?;
            self.ports.store.put_device(&device)?;
            return Err(RegistrationError::PolicyDenied(reasons));
        }
        if device_busy {
            // At most one live tenancy per device (REG §2 invariant).
            record.state = TenancyState::Held;
            record.reasons = vec!["device-has-live-tenancy".into()];
        }
        self.ports.store.put_tenancy(&record)?;
        self.ports.store.put_device(&device)?;
        if record.state == TenancyState::Pending && !self.policy.factory().registration.require_fingerprint_confirmation {
            record = self.approve(record, false)?;
        }
        Ok(Submitted { tenancy: record, words })
    }

    fn has_live_tenancy(&self, device: &RegisteredDevice) -> Result<bool, RegistrationError> {
        for t in &device.tenancies {
            if let Some(r) = self.ports.store.tenancy(t)?
                && matches!(r.state, TenancyState::Registered | TenancyState::Flagged)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The device a request comes from: an existing device of the account with the same
    /// attested serial, or a new one.
    fn device_for(
        &self,
        account: &AccountId,
        claims: &AttestationClaims,
        request: &RegistrationRequest,
    ) -> Result<RegisteredDevice, RegistrationError> {
        if let Some(serial) = &claims.device_serial
            && let Some(d) = self.ports.store.devices_of(account)?.into_iter().find(|d| d.hardware_id.as_ref() == Some(serial))
        {
            return Ok(d);
        }
        let n = self.ports.store.devices_of(account)?.len() + 1;
        Ok(RegisteredDevice {
            id: DeviceId(format!("dev:{}", hex8(request.tenancy.as_bytes()))),
            account: account.clone(),
            nickname: request.label.clone().unwrap_or_else(|| format!("device {n}")),
            words: request.fingerprint_words(),
            hardware_id: claims.device_serial.clone(),
            tenancies: vec![],
        })
    }

    // -----------------------------------------------------------------------------------
    // ConfirmFingerprint, ApproveHeld, RejectHeld (REG-021, REG-022, REG-030..032).

    /// `ConfirmFingerprint`: the account the token was issued to confirms the words match
    /// its device (REG-021). Registers the tenancy, or holds or denies it by policy.
    pub fn confirm(&self, account: &AccountId, tenancy: &TenancyId) -> Result<TenancyRecord, RegistrationError> {
        let mut record = self.tenancy(tenancy)?;
        if record.account != *account {
            return Err(RegistrationError::WrongAccount);
        }
        if record.state != TenancyState::Pending {
            return Err(RegistrationError::NotPending);
        }
        if self.now() > record.pending_until {
            record.state = TenancyState::Rejected;
            record.reasons = vec!["confirmation-expired".into()];
            self.ports.store.put_tenancy(&record)?;
            return Err(RegistrationError::ConfirmationExpired);
        }
        if !record.batch {
            self.check_device_limit(account, Some(&record.device), Subject::Tenancy(record.id))?;
        }
        self.approve(record, true)
    }

    fn approve(&self, mut record: TenancyRecord, confirmed: bool) -> Result<TenancyRecord, RegistrationError> {
        let serial = record.active_key(DeviceKeyKind::Signing).and_then(|k| k.claims.as_ref()).and_then(|c| c.device_serial.clone());
        let serial_status = match (&serial, self.ports.fleet) {
            (None, _) | (Some(_), None) => "absent",
            (Some(s), Some(f)) => {
                if f.knows(s) {
                    "matched"
                } else {
                    "unmatched"
                }
            }
        };
        let facts = Facts::from([
            ("fingerprintConfirmed".to_owned(), Value::Bool(confirmed)),
            ("serialStatus".to_owned(), Value::Text(serial_status.to_owned())),
            ("nonceOnly".to_owned(), Value::Bool(record.nonce_source == NonceSource::Device)),
        ]);
        let d = self.decide(DecisionPoint::RegistrationApprove, facts, Subject::Tenancy(record.id));
        record.reasons = d.reasons.clone();
        match d.verdict {
            Verdict::Allow | Verdict::Flag => {
                let serial = if serial_status == "matched" { serial } else { None };
                self.register(&mut record, serial)?;
            }
            Verdict::Hold => {
                record.state = TenancyState::Held;
                self.ports.store.put_tenancy(&record)?;
                self.notify(&record.account, PortalEvent::RegistrationHeld(record.id));
            }
            Verdict::Deny => {
                record.state = TenancyState::Rejected;
                self.ports.store.put_tenancy(&record)?;
                return Err(RegistrationError::PolicyDenied(d.reasons));
            }
        }
        Ok(record)
    }

    fn certificate_for(&self, record: &TenancyRecord, serial: Option<String>) -> Result<TenancyCertificate, RegistrationError> {
        let account = self.ports.store.account(&record.account)?.ok_or(RegistrationError::NotFound)?;
        let agreement = record.active_key(DeviceKeyKind::Agreement).ok_or(RegistrationError::NotFound)?;
        let mut cert = TenancyCertificate {
            tenancy: record.id,
            collector: account.collector.to_vec(),
            handle: record.handle,
            keys: record
                .keys
                .iter()
                .filter(|k| k.kind == DeviceKeyKind::Signing)
                .map(|k| CertifiedKey { index: k.index, public_key: k.public_key.clone() })
                .collect(),
            agreement_key: agreement.public_key.clone(),
            record_key: record.record_key,
            window: record.window,
            cohorts: record.cohorts.clone(),
            serial,
            issued_at: self.now(),
            policy: policy_address(&self.policy.sources),
            signer: self.config.signing_key,
            signature: fieldseal_kernel::crypto::Signature(vec![]),
        };
        cert.signature = self.sign(&tags::TENANCY_CERTIFICATE, &cert.signed_structure())?;
        Ok(cert)
    }

    /// Registers automatically (REG-030): issues the tenancy certificate (REG-032).
    fn register(&self, record: &mut TenancyRecord, serial: Option<String>) -> Result<(), RegistrationError> {
        record.certificate = Some(self.certificate_for(record, serial)?);
        record.state = TenancyState::Registered;
        self.ports.store.put_tenancy(record)?;
        self.notify(&record.account, PortalEvent::DeviceRegistered(record.device.clone()));
        Ok(())
    }

    /// `ApproveHeld`: an operator registers a held tenancy.
    pub fn approve_held(&self, operator: &AuthenticatedPerson, tenancy: &TenancyId) -> Result<TenancyRecord, RegistrationError> {
        if !operator.has(Role::Operator) {
            return Err(RegistrationError::NotAuthorised("approving a held registration needs the operator role"));
        }
        let mut record = self.tenancy(tenancy)?;
        if record.state != TenancyState::Held {
            return Err(RegistrationError::NotHeld);
        }
        record.reasons.push("approved-by-operator".into());
        self.register(&mut record, None)?;
        Ok(record)
    }

    /// `RejectHeld`: an operator rejects a held tenancy, with a reason shown on the portal.
    pub fn reject_held(
        &self,
        operator: &AuthenticatedPerson,
        tenancy: &TenancyId,
        reason: &str,
    ) -> Result<TenancyRecord, RegistrationError> {
        if !operator.has(Role::Operator) {
            return Err(RegistrationError::NotAuthorised("rejecting a held registration needs the operator role"));
        }
        let mut record = self.tenancy(tenancy)?;
        if record.state != TenancyState::Held {
            return Err(RegistrationError::NotHeld);
        }
        record.state = TenancyState::Rejected;
        record.reasons.push(format!("rejected-by-operator: {reason}"));
        self.ports.store.put_tenancy(&record)?;
        Ok(record)
    }

    // -----------------------------------------------------------------------------------
    // GetCertificate, status.

    /// A tenancy's state, for status polling by the runtime or the portal.
    pub fn status(&self, tenancy: &TenancyId) -> Result<TenancyRecord, RegistrationError> {
        self.tenancy(tenancy)
    }

    /// `GetCertificate`: the certificate of a registered tenancy.
    pub fn certificate(&self, tenancy: &TenancyId) -> Result<TenancyCertificate, RegistrationError> {
        let record = self.tenancy(tenancy)?;
        if !record.state.may_call_api() {
            return Err(revoked_or_unregistered(record.state));
        }
        record.certificate.ok_or(RegistrationError::NotRegistered)
    }

    // -----------------------------------------------------------------------------------
    // RollKey (REG-060, REG-061).

    fn roll(&self, request: &RegistrationRequest, via: &Submission) -> Result<Submitted, RegistrationError> {
        let roll = request.roll.as_ref().expect("roll request");
        let mut record = self.tenancy(&roll.tenancy)?;
        if !record.state.may_call_api() {
            return Err(revoked_or_unregistered(record.state));
        }
        let words = request.fingerprint_words();
        if record.keys.iter().any(|k| k.public_key == request.sign_pub) {
            // A retry of a roll already applied.
            return Ok(Submitted { tenancy: record, words });
        }
        let now = self.now();
        let token = self.check_token(&request.token, via, now)?;
        if token.account != record.account {
            return Err(RegistrationError::WrongAccount);
        }
        if request.nonce_source != NonceSource::Factory || request.nonce != token.token.nonce {
            return Err(RegistrationError::NonceMismatch);
        }
        verify_pop(&request.sign_pub, &request.nonce, &request.body_digest, &request.proof_of_possession)
            .map_err(|_| RegistrationError::ProofInvalid)?;
        let current = record.active_key(DeviceKeyKind::Signing).ok_or(RegistrationError::NotRegistered)?;
        verify_pop(&current.public_key, &request.nonce, &request.body_digest, &roll.signature)
            .map_err(|_| RegistrationError::ProofInvalid)?;
        let (sign_claims, agree_claims) = self.verify_evidence(request)?;
        self.ports.store.consume_token(&request.token, now)?;
        let reasons = self.sufficiency(request, &sign_claims, &agree_claims);
        if !reasons.is_empty() {
            return Err(RegistrationError::PolicyDenied(reasons));
        }
        let facts = Facts::from([("postureOk".to_owned(), Value::Bool(record.state == TenancyState::Registered))]);
        let d = self.decide(DecisionPoint::KeyRoll, facts, Subject::Tenancy(record.id));
        if !matches!(d.verdict, Verdict::Allow | Verdict::Flag) {
            return Err(RegistrationError::PolicyDenied(d.reasons));
        }
        let next = |kind| record.keys.iter().filter(|k| k.kind == kind).map(|k| k.index + 1).max().unwrap_or(0);
        let (next_sign, next_agree) = (next(DeviceKeyKind::Signing), next(DeviceKeyKind::Agreement));
        for k in record.keys.iter_mut().filter(|k| k.state == KeyState::Active) {
            k.state = KeyState::Rolled;
        }
        record.keys.push(RegisteredKey {
            index: next_sign,
            kind: DeviceKeyKind::Signing,
            public_key: request.sign_pub.clone(),
            evidence: evidence_of(request, DeviceKeyKind::Signing),
            claims: Some(sign_claims),
            state: KeyState::Active,
        });
        record.keys.push(RegisteredKey {
            index: next_agree,
            kind: DeviceKeyKind::Agreement,
            public_key: request.agree_pub.clone(),
            evidence: evidence_of(request, DeviceKeyKind::Agreement),
            claims: Some(agree_claims),
            state: KeyState::Active,
        });
        // The roll request is signed by both keys, so the profile in it is the one the runtime
        // now reports; it replaces the recorded one, whether higher or lower (REG-091).
        record.profile = request.profile.clone();
        record.words = words;
        record.last_seen = Some(now);
        let serial = record.certificate.as_ref().and_then(|c| c.serial.clone());
        record.certificate = Some(self.certificate_for(&record, serial)?);
        self.ports.store.put_tenancy(&record)?;
        Ok(Submitted { tenancy: record, words })
    }

    // -----------------------------------------------------------------------------------
    // ListDevices, MarkLost, Retire, IssueCloseCertificate (REG-043, REG-062..065).

    /// `ListDevices`: an account's devices with their latest tenancy (REG-043).
    pub fn list_devices(&self, account: &AccountId) -> Result<Vec<DeviceView>, RegistrationError> {
        let mut out = Vec::new();
        for device in self.ports.store.devices_of(account)? {
            let tenancy = match device.tenancies.last() {
                Some(t) => self.ports.store.tenancy(t)?,
                None => None,
            };
            out.push(DeviceView { device, tenancy });
        }
        Ok(out)
    }

    /// Pending requests of an account, awaiting confirmation (REG-021); a batch token's
    /// requests are listed together (REG-044).
    pub fn pending(&self, account: &AccountId) -> Result<Vec<TenancyRecord>, RegistrationError> {
        let mut out: Vec<TenancyRecord> =
            self.ports.store.tenancies_of(account)?.into_iter().filter(|t| t.state == TenancyState::Pending).collect();
        out.sort_by_key(|t| (t.token, t.id));
        Ok(out)
    }

    /// Every held tenancy of an account (for an operator's review).
    pub fn held(&self, account: &AccountId) -> Result<Vec<TenancyRecord>, RegistrationError> {
        Ok(self.ports.store.tenancies_of(account)?.into_iter().filter(|t| t.state == TenancyState::Held).collect())
    }

    fn live_tenancy_of(&self, person: &AuthenticatedPerson, device: &DeviceId) -> Result<TenancyRecord, RegistrationError> {
        let d = self.ports.store.device(device)?.ok_or(RegistrationError::NotFound)?;
        if d.account != person.account && !person.has(Role::Operator) {
            return Err(RegistrationError::WrongAccount);
        }
        let id = d.tenancies.last().ok_or(RegistrationError::NotFound)?;
        self.tenancy(id)
    }

    /// Closes `record`: sets its cutoff to the highest `seq` received (REG-062), moves it
    /// to `state` and issues a close (or reset) certificate (REG-064).
    fn close_with(
        &self,
        mut record: TenancyRecord,
        state: TenancyState,
        reason: CloseReason,
    ) -> Result<CloseCertificate, RegistrationError> {
        let received = self.ports.progress.highest_received(&record.id).map_err(|e| RegistrationError::Port(e.to_string()))?;
        let cutoff = record.cutoff.or(received).unwrap_or(Seq(0));
        let mut cert = CloseCertificate {
            tenancy: record.id,
            cutoff,
            reason,
            issued_at: self.now(),
            signer: self.config.signing_key,
            signature: fieldseal_kernel::crypto::Signature(vec![]),
        };
        cert.signature = self.sign(&CloseCertificate::tag(reason), &cert.signed_structure())?;
        cert.encode().map_err(RegistrationError::Malformed)?;
        record.cutoff = Some(cutoff);
        record.state = state;
        record.reasons.push(format!("closed: {}", reason.as_str()));
        self.ports.store.put_tenancy(&record)?;
        Ok(cert)
    }

    /// `MarkLost`: the collector (or an operator) reports a device lost. Sets the cutoff,
    /// marks it `lost` and issues a close certificate (REG-062). Intake enforces the cutoff
    /// from the registry; nothing depends on the device (REG-063).
    pub fn mark_lost(&self, person: &AuthenticatedPerson, device: &DeviceId) -> Result<CloseCertificate, RegistrationError> {
        let record = self.live_tenancy_of(person, device)?;
        let account = record.account.clone();
        let cert = self.close_with(record, TenancyState::Lost, CloseReason::Lost)?;
        self.notify(&account, PortalEvent::DeviceMarkedLost(device.clone()));
        Ok(cert)
    }

    /// `Retire`: the device's loan ends.
    pub fn retire(&self, person: &AuthenticatedPerson, device: &DeviceId) -> Result<CloseCertificate, RegistrationError> {
        let record = self.live_tenancy_of(person, device)?;
        self.close_with(record, TenancyState::Retired, CloseReason::Returned)
    }

    /// `IssueCloseCertificate`: an operator closes a tenancy, for example with a reset
    /// certificate for a forgotten PIN (REG-065).
    pub fn close(&self, operator: &AuthenticatedPerson, tenancy: &TenancyId, reason: CloseReason) -> Result<CloseCertificate, RegistrationError> {
        if !operator.has(Role::Operator) {
            return Err(RegistrationError::NotAuthorised("closing a tenancy needs the operator role"));
        }
        let record = self.tenancy(tenancy)?;
        self.close_with(record, TenancyState::Closing, reason)
    }

    // -----------------------------------------------------------------------------------
    // CheckPosture (REG-071, REG-072, REG-080..082).

    /// Issues a posture nonce to an authenticated tenancy (REG-071).
    pub fn posture_nonce(&self, tenancy: &TenancyId) -> Result<Nonce, RegistrationError> {
        let nonce = Nonce::from(self.random::<32>());
        let expires_at = self.now().checked_add(self.config.posture_nonce_ttl_ms).unwrap_or(AuthorityTime(u64::MAX));
        self.ports.store.put_nonce(&IssuedNonce { nonce, tenancy: *tenancy, expires_at })?;
        Ok(nonce)
    }

    /// `CheckPosture`: evaluates a posture report at `posture.recheck` (REG-081). Any
    /// missing required restriction, `unknown` ones when policy flags them, and any failing
    /// platform check flag the tenancy, pausing bundle releases; a clean report clears the
    /// flag. Neither revokes the tenancy nor touches intake (REG-082).
    pub fn check_posture(&self, report: &[u8]) -> Result<PostureOutcome, RegistrationError> {
        let report = decode_posture(report).map_err(RegistrationError::Malformed)?;
        let mut record = self.tenancy(&report.tenancy)?;
        if !record.state.may_call_api() {
            return Err(revoked_or_unregistered(record.state));
        }
        let now = self.now();
        if !self.ports.store.take_nonce(&report.nonce, &report.tenancy, now)? {
            return Err(RegistrationError::NonceMismatch);
        }
        let key = record.active_key(DeviceKeyKind::Signing).ok_or(RegistrationError::NotRegistered)?.clone();
        verify_pop(&key.public_key, &report.nonce, &report.body_digest, &report.proof_of_possession)
            .map_err(|_| RegistrationError::ProofInvalid)?;

        let mut reasons = Vec::new();
        let claims = match &report.evidence {
            Some(e) => match VerifyEvidence::new(self.ports.verifiers.clone()).verify(self.bundle, e, &report.nonce, &key.public_key) {
                Ok(c) => Some(c),
                Err(err) => {
                    reasons.push(format!("posture-evidence-rejected: {err}"));
                    None
                }
            },
            None => key.claims.clone(),
        };
        let factory = self.policy.factory();
        let required: Vec<String> = self.policy.runtime().device.required_restrictions.iter().map(|r| r.as_str().to_owned()).collect();
        let flag_unknown = factory.posture.unknown_restriction == UnknownRestriction::Flag;
        reasons.extend(report.gaps(&required, flag_unknown).into_iter().map(|g| format!("restriction-not-in-force: {g}")));
        match claims.as_ref().map(|c| (c, policy_level_name(c.security_level))) {
            Some((c, Some(level))) => {
                let facts = Facts::from([
                    ("verifiedBoot".to_owned(), Value::Bool(c.boot_state == Some(BootState::Verified))),
                    ("bootloaderLocked".to_owned(), Value::Bool(c.bootloader_locked == Some(true))),
                    ("securityLevel".to_owned(), Value::Text(level.to_owned())),
                    ("osPatchLevel".to_owned(), Value::Text(c.os_patch_level.clone().unwrap_or_else(|| "0001-01-01".into()))),
                    (
                        "unknownRestriction".to_owned(),
                        Value::Bool(report.restrictions.values().any(|r| *r == crate::domain::ReportedRestriction::Unknown)),
                    ),
                ]);
                let d = self.decide(DecisionPoint::PostureRecheck, facts, Subject::Tenancy(record.id));
                if d.verdict != Verdict::Allow {
                    reasons.extend(d.reasons);
                }
            }
            Some((_, None)) if self.config.unattested == UnattestedKeys::AllowNonProduction => {}
            Some((_, None)) => reasons.push("unattested-key".into()),
            None => {}
        }
        reasons.sort();
        reasons.dedup();
        let ok = reasons.is_empty();
        record.state = if ok { TenancyState::Registered } else { TenancyState::Flagged };
        record.reasons = reasons.clone();
        record.last_seen = Some(now);
        self.ports.store.put_tenancy(&record)?;
        Ok(PostureOutcome { ok, reasons })
    }

    // -----------------------------------------------------------------------------------
    // API authentication (REG-070, WIRE-170..172) and IssueApiToken.

    /// Authenticates one runtime API request by its PoP header (WIRE-171): the token must
    /// name a tenancy allowed to call the API, match `method` and `url`, be within 300 s of
    /// the factory's clock, carry an unseen `jti`, and be signed by the tenancy's current
    /// signing key. With `access`, the token must also carry its hash (`ath`) and the access
    /// token must be live and bound to the same tenancy and key.
    pub fn authenticate_api(
        &self,
        header: &str,
        method: &str,
        url: &str,
        access: Option<&[u8; 32]>,
    ) -> Result<TenancyRecord, RegistrationError> {
        let pop = PopToken::from_header(header).map_err(RegistrationError::Malformed)?;
        let mut record = self.ports.store.tenancy(&pop.tenancy)?.ok_or(RegistrationError::NotRegistered)?;
        if !record.state.may_call_api() {
            return Err(revoked_or_unregistered(record.state));
        }
        if !pop.method.eq_ignore_ascii_case(method) || pop.url != url {
            return Err(RegistrationError::ProofInvalid);
        }
        let now = self.now();
        if now.0.abs_diff(pop.iat.0) > POP_WINDOW_MS {
            return Err(RegistrationError::ProofInvalid);
        }
        let key = record.active_key(DeviceKeyKind::Signing).ok_or(RegistrationError::NotRegistered)?;
        pop.verify_signature(&key.public_key).map_err(|_| RegistrationError::ProofInvalid)?;
        let key_id = crate::domain::wire::device_key_id(&key.public_key);
        match (access, pop.ath) {
            (None, None) => {}
            (Some(value), Some(ath)) if sha256(value) == ath => {
                let t = self.ports.store.access_token(value)?.ok_or(RegistrationError::ProofInvalid)?;
                if t.tenancy != record.id || t.key != key_id || now > t.expires_at {
                    return Err(RegistrationError::ProofInvalid);
                }
            }
            _ => return Err(RegistrationError::ProofInvalid),
        }
        let until = AuthorityTime(now.0.saturating_add(POP_WINDOW_MS));
        if !self.ports.store.record_jti(&pop.tenancy, &pop.jti, until, now)? {
            return Err(RegistrationError::Replay);
        }
        record.last_seen = Some(now);
        self.ports.store.put_tenancy(&record)?;
        Ok(record)
    }

    /// `IssueApiToken`: a short-lived access token bound to the tenancy's current signing
    /// key, for a request already authenticated by [`Self::authenticate_api`].
    pub fn issue_api_token(&self, record: &TenancyRecord) -> Result<AccessToken, RegistrationError> {
        let key = record.active_key(DeviceKeyKind::Signing).ok_or(RegistrationError::NotRegistered)?;
        let token = AccessToken {
            value: self.random(),
            tenancy: record.id,
            key: crate::domain::wire::device_key_id(&key.public_key),
            expires_at: self.now().checked_add(self.config.access_token_ttl_ms).unwrap_or(AuthorityTime(u64::MAX)),
        };
        self.ports.store.put_access_token(&token)?;
        Ok(token)
    }
}

fn evidence_of(request: &RegistrationRequest, kind: DeviceKeyKind) -> fieldseal_trust::domain::AttestationEvidence {
    request.evidence.iter().find(|e| e.kind == kind).map(|e| e.evidence.clone()).expect("verified evidence is present")
}

fn revoked_or_unregistered(state: TenancyState) -> RegistrationError {
    match state {
        TenancyState::Lost | TenancyState::Closing | TenancyState::Closed | TenancyState::Retired => RegistrationError::Revoked,
        _ => RegistrationError::NotRegistered,
    }
}

fn policy_level_name(level: SecurityLevel) -> Option<&'static str> {
    match level {
        SecurityLevel::Software => None,
        SecurityLevel::Tee => Some("tee"),
        SecurityLevel::StrongBox => Some("strongbox"),
        SecurityLevel::SecureElement => Some("secure-element"),
        SecurityLevel::Tpm => Some("tpm"),
    }
}
