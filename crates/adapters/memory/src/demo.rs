//! A whole demo factory for Distribution tests and `fieldseal bundle`: a root, a factory
//! key, a registration key, a receipt key, two publishers and a builder certified in a signed
//! trust bundle; a real transparency log; registered tenancies with real software keys;
//! rosters; a release policy; and a bundle builder wired over all of them.
//!
//! Everything comes from a seed, so the same inputs give the same bytes. Keys sit in
//! process memory and devices are unattested unless a test says otherwise: **for tests, the
//! CLI and practice only**, never a hardware boundary.

use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_distribution::application::{BuildBundle, BuildRequest, BuiltBundle, BundleBuilder, FactoryIdentity, FactoryPorts};
use fieldseal_distribution::domain::{DistributionError, Roster, RuntimeProfile};
use fieldseal_instrument::domain::SchemaVersion;
use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{CollectionPeriodId, CohortId, ContentAddress, Generation, KeyId, ReviewerId, Salt, TenancyHandle, TenancyId};
use fieldseal_kernel::seal::{RecipientKey, RecipientSecret, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::cbor;
use fieldseal_policy::application::{Decide, PolicyService};
use fieldseal_policy::domain::{Controls, PolicyDocument, PublishedPolicy, PublishingPolicy, decode_document};
use fieldseal_policy::fixtures::DocBuilder;
use fieldseal_policy::ports::PolicyEngine;
use fieldseal_publishing::application::{
    BuildInput, BuildProvenance, Publish, SignPublication, SignWithdrawal, VerifyPublication, Withdraw,
};
use fieldseal_publishing::domain::{
    Artefact, ArtefactKind, BuilderId, Publication, Review, ReviewDecision, RevisionId, SourceRef, Withdrawal, WithdrawalDraft,
    WithdrawalStatement,
};
use fieldseal_publishing::ports::ReviewSystem;
use fieldseal_registration::contract::sample_tenancy;
use fieldseal_registration::domain::wire::{CertifiedKey, TenancyCertificate};
use fieldseal_registration::domain::{
    AccountId, CohortAssignment, DeviceId, KeyState, RegisteredDevice, RegisteredKey, TenancyState, Window,
};
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::application::Authority;
use fieldseal_trust::domain::{
    AttestationClaims, BootState, BundleVersion, Ceremony, CollectionPeriod, CustodyKey, DeviceKeyKind, IssueTerms, RecordKeyTerms, Retention, KeyAlgorithm, KeyCertificate, KeyRole,
    RuntimeBuild, SecurityLevel, Threshold, TrustBundle, TrustBundleContents, TrustStore,
};
use fieldseal_trust::ports::KeyCustody;

use crate::collection::LocalTransport;
use crate::distribution::{sign_time_token, MemoryAnchorSource, MemoryBundleStore, MemoryRosterSource, MemoryRuntimeProfiles, SoftwareAgreementKey};
use crate::policy::{BuiltInPolicyEngine, MemoryDecisionLog, MemoryPolicySource};
use crate::publishing::{MemoryArtefactRegistry, MemoryReviewSystem, MemoryTransparencyLog};
use crate::registration::MemoryRegistryStore;
use crate::trust::{MemoryKeyCustody, SeededRandom};

/// The instrument-schema version the demo runtime implements.
pub const DEMO_SCHEMA: SchemaVersion = SchemaVersion { major: 1, minor: 0, patch: 0 };

const BUILDER: &str = "https://ci.example.org/builders/fieldseal-demo";
const SOURCE: &str = "https://git.example.org/authority/artefacts";
const CALLER: &str = "demo-factory";

/// The release policy a world publishes: its address and decoded document.
#[derive(Clone, Debug)]
pub struct DemoPolicy {
    /// The published policy's content address.
    pub address: ContentAddress,
    /// The publication.
    pub publication: Publication,
    /// The decoded document.
    pub document: PolicyDocument,
}

/// A registered demo device: the tenancy and the keys the runtime would hold.
#[derive(Clone, Debug)]
pub struct DemoDevice {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The device record's identifier.
    pub device: DeviceId,
    /// The agreement public key bundles are sealed to.
    pub agreement_public: fieldseal_kernel::crypto::P256PublicKey,
    secret: Option<[u8; 32]>,
}

impl DemoDevice {
    /// The agreement key as a runtime would hold it (software, for tests).
    pub fn agreement_key(&self) -> SoftwareAgreementKey {
        SoftwareAgreementKey::new(RecipientSecret::from_bytes(Suite::Fs1P, &self.secret.expect("this device's key is held elsewhere")).expect("a valid scalar"))
            .expect("a valid key")
    }

    /// The agreement private key's bytes, for the CLI's software key files, when the world
    /// derived the device's keys.
    pub fn agreement_secret(&self) -> Option<[u8; 32]> {
        self.secret
    }
}

/// The keys [`DemoWorld::add_edge_services`] adds.
#[derive(Clone, Debug)]
pub struct EdgeServices {
    /// The registration key devices seal requests to (X25519).
    pub sealing: CustodyKey,
    /// The key that answers upload challenges (P-256).
    pub receiver: KeyId,
    /// The receiver key's certificate, as the trust bundle lists it.
    pub receiver_certificate: KeyCertificate,
}

/// The whole demo factory.
pub struct DemoWorld {
    /// Every private key.
    pub custody: MemoryKeyCustody<SeededRandom>,
    /// Randomness for sealing.
    pub random: SeededRandom,
    /// The trust bundle a runtime is provisioned with.
    pub trust: TrustBundle,
    /// The publishing policy.
    pub publishing: PublishingPolicy,
    /// The factory signing key.
    pub factory: KeyId,
    /// Its certificate (the trust bundle also pins it).
    pub factory_certificate: KeyCertificate,
    /// The two publishers' keys.
    pub publishers: Vec<KeyId>,
    /// The receipt-and-time key.
    pub receipt: KeyId,
    /// The registration signing key.
    pub registration: KeyId,
    /// The record key of the demo collection period (X25519); tenancy certificates name it.
    pub record: CustodyKey,
    /// Tenancies and devices.
    pub registry: MemoryRegistryStore,
    /// Published artefacts and withdrawals.
    pub artefacts: MemoryArtefactRegistry,
    /// Rosters.
    pub rosters: MemoryRosterSource,
    /// What each runtime reported.
    pub profiles: MemoryRuntimeProfiles,
    /// Bundles built.
    pub bundles: MemoryBundleStore,
    /// The release policy published for the world.
    pub policy: DemoPolicy,
    /// The world's start: keys are valid from here.
    pub t0: AuthorityTime,
    /// The world's present time: artefacts are published before it and bundles after it.
    pub now: AuthorityTime,
    log: MemoryTransparencyLog<LocalTransport>,
    root: KeyCertificate,
    builder: KeyId,
    next_anchor: AtomicU64,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Everything publishing needs, borrowed from a world under construction.
struct Publisher<'a> {
    custody: &'a MemoryKeyCustody<SeededRandom>,
    log: &'a MemoryTransparencyLog<LocalTransport>,
    artefacts: &'a MemoryArtefactRegistry,
    trust: &'a TrustBundle,
    policy: &'a PublishingPolicy,
    builder: KeyId,
    publishers: &'a [KeyId],
    receipt: KeyId,
    finished: AuthorityTime,
    /// Whether the checkpoint is accompanied by a time token (PUB-072).
    dated: bool,
}

impl Publisher<'_> {
    /// Builds, reviews twice, signs with every publisher, logs and registers one artefact.
    fn publish(&self, kind: ArtefactKind, name: &str, version: &str, bytes: Vec<u8>, salt: Option<Salt>) -> Result<Publication, String> {
        let artefact = Artefact::new(kind, name, version, bytes, salt).map_err(err)?;
        let reviews = MemoryReviewSystem::new();
        for who in ["reviewer-1", "reviewer-2"] {
            reviews.grant_kind(&ReviewerId::new(who).map_err(err)?, artefact.kind());
            reviews
                .record(&Review {
                    address: *artefact.address(),
                    revision: RevisionId("rev-1".into()),
                    reviewer: ReviewerId::new(who).map_err(err)?,
                    decision: ReviewDecision::Approve,
                })
                .map_err(err)?;
        }
        let input = BuildInput {
            artefact,
            source: SourceRef { uri: SOURCE.into(), revision: RevisionId("rev-1".into()) },
            author: ReviewerId::new("author-1").map_err(err)?,
            builder: BuilderId(BUILDER.into()),
            definition: sha256(b"fieldseal.dev/demo/build/v1"),
            finished: self.finished,
            languages: Vec::new(),
        };
        let draft = BuildProvenance::new(self.custody, &reviews, self.policy, self.builder, CALLER).build(input).map_err(err)?;
        let verifier = VerifyPublication::new(TrustStore::new(self.trust), self.policy);
        let signer = SignPublication::new(self.custody, &verifier, CALLER);
        let mut d = draft;
        for p in self.publishers {
            d = signer.sign(&d, p).map_err(err)?;
        }
        // The tree head is dated by a time token from the receipt-and-time key (PUB-072).
        let publish = Publish::new(self.log, self.artefacts, &verifier);
        let publish = if self.dated {
            publish.with_checkpoint_time(sign_time_token(self.custody, &self.receipt, self.finished).map_err(err)?.encode())
        } else {
            publish
        };
        publish.publish(&d, &[]).map_err(err)
    }
}

impl DemoWorld {
    /// A world derived from `seed`, starting at `t0`; its present is one day later.
    pub fn new(seed: u64, t0: AuthorityTime) -> Result<Self, String> {
        let custody = MemoryKeyCustody::new(SeededRandom::new(seed));
        let a = Authority::new(&custody, CALLER);
        let day = AuthorityTime::DAY;
        let root = a
            .init_root(Ceremony {
                authority: "demo-authority".into(),
                threshold: Threshold::DEFAULT,
                custodians: vec!["custodian-a".into(), "custodian-b".into(), "custodian-c".into()],
                witnesses: vec!["witness-1".into()],
                held_at: t0,
                not_before: t0,
                not_after: AuthorityTime(t0.0 + 5 * 365 * day),
            })
            .map_err(err)?
            .root;
        let mut certificates = Vec::new();
        let mut serial = 0;
        let mut certify = |purpose: Purpose, days: u64| -> Result<(KeyId, KeyCertificate), String> {
            let key = custody.generate(KeyRole::Purpose(purpose), KeyAlgorithm::P256).map_err(err)?;
            serial += 1;
            let cert = a
                .issue(
                    &root,
                    &a.request(&key.id, Some(purpose)).map_err(err)?,
                    IssueTerms { purpose, record: None, not_before: t0, not_after: AuthorityTime(t0.0 + days * day), serial },
                )
                .map_err(err)?;
            certificates.push(cert.clone());
            Ok((key.id, cert))
        };
        let (factory, factory_certificate) = certify(Purpose::Factory, 300)?;
        let (registration, _) = certify(Purpose::Registration, 300)?;
        let (receipt, _) = certify(Purpose::Receipt, 300)?;
        let (builder, _) = certify(Purpose::Builder, 300)?;
        let (pa, _) = certify(Purpose::Publisher, 700)?;
        let (pb, _) = certify(Purpose::Publisher, 700)?;
        let publishers = vec![pa, pb];
        let record = custody.generate(KeyRole::Purpose(Purpose::Record), KeyAlgorithm::X25519).map_err(err)?;
        let period = CollectionPeriod::new(CollectionPeriodId::new("demo-period").map_err(err)?, t0, AuthorityTime(t0.0 + 180 * day)).map_err(err)?;
        let record_certificate = a
            .open_collection_period(
                &root,
                &a.request(&record.id, Some(Purpose::Record)).map_err(err)?,
                RecordKeyTerms { period, retention: Retention(180 * day) },
                t0,
                serial + 1,
            )
            .map_err(err)?;
        certificates.push(record_certificate);
        let log = MemoryTransparencyLog::new("log.demo.example/v1", LocalTransport);
        let trust = a
            .build_bundle(
                TrustBundleContents {
                    name: "demo-authority".into(),
                    version: BundleVersion::parse("1.0.0").map_err(err)?,
                    issued: t0,
                    roots: vec![root.clone()],
                    certificates,
                    publishers: ArtefactKind::ALL.iter().map(|k| (k.as_str().to_owned(), publishers.clone())).collect(),
                    logs: vec![log.pin()],
                    ..TrustBundleContents::default()
                },
                &[&root],
                None,
            )
            .map_err(err)?;
        let mut publishing = Controls::defaults().publishing();
        publishing.allowed_builders = vec![BUILDER.into()];
        publishing.allowed_sources = vec![SOURCE.into()];
        let now = AuthorityTime(t0.0 + day);
        let artefacts = MemoryArtefactRegistry::new();
        let policy = {
            let p = Publisher {
                custody: &custody,
                log: &log,
                artefacts: &artefacts,
                trust: &trust,
                policy: &publishing,
                builder,
                publishers: &publishers,
                receipt,
                finished: AuthorityTime(t0.0 + 3_600_000),
                dated: true,
            };
            let value = DocBuilder::deployment("baseline", "1.0.0").build();
            let bytes = cbor::encode(&value).map_err(err)?;
            let publication = p.publish(ArtefactKind::Policy, "baseline", "1.0.0", bytes, None)?;
            let document = decode_document(&value).document.ok_or("the demo policy document is invalid")?;
            DemoPolicy { address: *publication.address(), publication, document }
        };
        Ok(Self {
            custody,
            random: SeededRandom::new(seed ^ 0x5eed),
            trust,
            publishing,
            factory,
            factory_certificate,
            publishers,
            receipt,
            registration,
            record,
            registry: MemoryRegistryStore::new(),
            artefacts,
            rosters: MemoryRosterSource::new(),
            profiles: MemoryRuntimeProfiles::new(),
            bundles: MemoryBundleStore::new(),
            policy,
            t0,
            now,
            log,
            root,
            builder,
            next_anchor: AtomicU64::new(now.0 + AuthorityTime::SECOND),
        })
    }

    /// Publishes an artefact: reviewed twice, signed by both publishers, logged. An
    /// instrument needs a `salt` (ADR 0027).
    pub fn publish(&self, kind: ArtefactKind, name: &str, version: &str, bytes: Vec<u8>, salt: Option<Salt>) -> Result<Publication, String> {
        self.publish_with(kind, name, version, bytes, salt, true)
    }

    /// Like [`DemoWorld::publish`], but `dated: false` publishes with no time token
    /// accompanying the checkpoint: a runtime treats such a tree head as too old (PUB-072).
    pub fn publish_with(&self, kind: ArtefactKind, name: &str, version: &str, bytes: Vec<u8>, salt: Option<Salt>, dated: bool) -> Result<Publication, String> {
        Publisher {
            custody: &self.custody,
            log: &self.log,
            artefacts: &self.artefacts,
            trust: &self.trust,
            policy: &self.publishing,
            builder: self.builder,
            publishers: &self.publishers,
            receipt: self.receipt,
            finished: AuthorityTime(self.t0.0 + 3_600_000),
            dated,
        }
        .publish(kind, name, version, bytes, salt)
    }

    /// Publishes under `policy`, signed by `signers` only: what a publisher does when it
    /// writes the policy it is checked by (a test of the factory's trust in its release
    /// policy).
    #[allow(clippy::too_many_arguments)]
    pub fn publish_under(&self, policy: &PublishingPolicy, signers: &[KeyId], kind: ArtefactKind, name: &str, version: &str, bytes: Vec<u8>, salt: Option<Salt>) -> Result<Publication, String> {
        Publisher {
            custody: &self.custody,
            log: &self.log,
            artefacts: &self.artefacts,
            trust: &self.trust,
            policy,
            builder: self.builder,
            publishers: signers,
            receipt: self.receipt,
            finished: AuthorityTime(self.t0.0 + 3_600_000),
            dated: true,
        }
        .publish(kind, name, version, bytes, salt)
    }

    /// The salt an instrument is published with: a fixed function of its name, so the salted
    /// fingerprint of a survey is the same in every world and on every run.
    #[must_use]
    pub fn salt_for(name: &str) -> Salt {
        Salt::from(*sha256(&[b"fieldseal.dev/demo/salt".as_slice(), name.as_bytes()].concat()).as_bytes())
    }

    /// Withdraws a publication, signed by both publishers and logged.
    pub fn withdraw(&self, publication: &Publication, reason: &str) -> Result<Withdrawal, String> {
        let verifier = VerifyPublication::new(TrustStore::new(&self.trust), &self.publishing);
        let signer = SignWithdrawal::new(&self.custody, &verifier, CALLER);
        let mut draft = WithdrawalDraft { statement: WithdrawalStatement::of(publication, reason, self.now), approvals: vec![] };
        for k in &self.publishers {
            draft = signer.sign(&draft, publication, k).map_err(err)?;
        }
        Withdraw::new(&self.log, &self.artefacts, &verifier).withdraw(&draft, publication).map_err(err)
    }

    /// Registers a device: a tenancy in state `registered` with a tenancy certificate, real
    /// software keys derived from `label`, and the cohorts at their generations. With
    /// `attested` its keys carry hardware claims (INV-10); without, they are software keys.
    /// `profile` is what its runtime reported (DIS-012, DIS-017).
    pub fn register(&self, label: &str, cohorts: &[(&str, u32)], attested: bool, profile: RuntimeProfile) -> Result<DemoDevice, String> {
        let scalar = |purpose: &str| *sha256(format!("fieldseal.dev/demo/{purpose}/{label}").as_bytes()).as_bytes();
        let sign = SigningKey::from_scalar(&scalar("sign")).map_err(err)?;
        let agree_secret = scalar("agree");
        let RecipientKey::P256(agreement_public) = RecipientSecret::from_bytes(Suite::Fs1P, &agree_secret).map_err(err)?.public().map_err(err)? else {
            return Err("an fs1-p key".into());
        };
        self.register_keys(label, &sign.public_key(), &agreement_public, Some(agree_secret), cohorts, attested, profile)
    }

    /// Registers a device whose keys are held elsewhere (for example by a simulated
    /// runtime): the tenancy is the SHA-256 of `sign_public` (WIRE-140) and bundles are
    /// sealed to `agreement_public`.
    #[allow(clippy::too_many_arguments)]
    pub fn register_keys(
        &self,
        label: &str,
        sign_public: &fieldseal_kernel::crypto::P256PublicKey,
        agreement_public: &fieldseal_kernel::crypto::P256PublicKey,
        secret: Option<[u8; 32]>,
        cohorts: &[(&str, u32)],
        attested: bool,
        profile: RuntimeProfile,
    ) -> Result<DemoDevice, String> {
        let agreement_public = agreement_public.clone();
        let tenancy = TenancyId::from(*sha256(sign_public.as_bytes()).as_bytes());
        let device = DeviceId(format!("device-{label}"));
        let account = AccountId(format!("account-{label}"));
        let assignments: Vec<CohortAssignment> = cohorts
            .iter()
            .map(|(c, g)| Ok(CohortAssignment { cohort: CohortId::new(*c).map_err(err)?, generation: Generation(*g) }))
            .collect::<Result<_, String>>()?;
        let window = Window { not_before: self.t0, not_after: AuthorityTime(self.t0.0 + 200 * AuthorityTime::DAY), grace_ms: 30 * AuthorityTime::DAY };
        let handle = TenancyHandle::from(<[u8; 16]>::try_from(&sha256(label.as_bytes()).as_bytes()[..16]).expect("16 bytes"));
        let record_key = self.record.id;
        let mut certificate = TenancyCertificate {
            tenancy,
            collector: b"demo-collector".to_vec(),
            handle,
            keys: vec![CertifiedKey { index: 0, public_key: sign_public.clone() }],
            agreement_key: agreement_public.clone(),
            record_key,
            window,
            cohorts: assignments.clone(),
            serial: None,
            issued_at: self.now,
            policy: ContentAddress::of(b"fieldseal.dev/demo/factory-policy"),
            signer: self.registration,
            signature: fieldseal_kernel::crypto::Signature(vec![0; 64]),
        };
        certificate.signature = self
            .custody
            .sign(&self.registration, KeyRole::Purpose(Purpose::Registration), &tags::TENANCY_CERTIFICATE, &certificate.signed_structure(), CALLER)
            .map_err(err)?;
        let claims = |kind| {
            attested.then(|| AttestationClaims {
                security_level: SecurityLevel::Tee,
                origin_generated: true,
                kind,
                unlocked_required: Some(true),
                challenge: fieldseal_kernel::id::Nonce::from([0; 32]),
                app_id: Some("fieldseal-demo".to_owned()),
                app_version: Some("1.0.0".to_owned()),
                os_patch_level: None,
                boot_state: Some(BootState::Verified),
                bootloader_locked: Some(true),
                device_serial: None,
            })
        };
        let evidence = |kind: DeviceKeyKind| fieldseal_trust::domain::AttestationEvidence { format: "demo".into(), data: vec![kind as u8] };
        let mut record = sample_tenancy(1, &account.0);
        record.id = tenancy;
        record.handle = handle;
        record.account = account.clone();
        record.device = device.clone();
        record.state = TenancyState::Registered;
        record.keys = vec![
            RegisteredKey {
                index: 0,
                kind: DeviceKeyKind::Signing,
                public_key: sign_public.clone(),
                evidence: evidence(DeviceKeyKind::Signing),
                claims: claims(DeviceKeyKind::Signing),
                state: KeyState::Active,
            },
            RegisteredKey {
                index: 0,
                kind: DeviceKeyKind::Agreement,
                public_key: agreement_public.clone(),
                evidence: evidence(DeviceKeyKind::Agreement),
                claims: claims(DeviceKeyKind::Agreement),
                state: KeyState::Active,
            },
        ];
        record.window = window;
        record.record_key = record_key;
        record.cohorts = assignments;
        record.certificate = Some(certificate);
        self.registry.put_tenancy(&record).map_err(err)?;
        self.registry
            .put_device(&RegisteredDevice {
                id: device.clone(),
                account,
                nickname: label.into(),
                words: record.words,
                hardware_id: None,
                tenancies: vec![tenancy],
            })
            .map_err(err)?;
        self.profiles.record(tenancy, profile);
        Ok(DemoDevice { tenancy, device, agreement_public, secret })
    }

    /// Sets a tenancy's state.
    pub fn set_state(&self, tenancy: &TenancyId, state: TenancyState) -> Result<(), String> {
        let mut record = self.registry.tenancy(tenancy).map_err(err)?.ok_or("no such tenancy")?;
        record.state = state;
        self.registry.put_tenancy(&record).map_err(err)
    }

    /// Sets the rosters the source returns for a device's tenancy.
    pub fn assign_rosters(&self, device: &DemoDevice, rosters: Vec<Roster>) {
        self.rosters.assign(device.tenancy, rosters);
    }

    /// The policy service with the built-in engine over the world's published release policy.
    pub fn built_in_policy(&self) -> PolicyService<MemoryPolicySource, BuiltInPolicyEngine, MemoryDecisionLog> {
        self.policy_service(BuiltInPolicyEngine)
    }

    /// The policy service with another engine.
    pub fn policy_service<E: PolicyEngine>(&self, engine: E) -> PolicyService<MemoryPolicySource, E, MemoryDecisionLog> {
        let published = PublishedPolicy { address: self.policy.address, document: self.policy.document.clone() };
        PolicyService::new(MemoryPolicySource::new(vec![published]), engine, MemoryDecisionLog::new())
    }

    /// The factory's signing identity, presenting its certificate.
    pub fn identity(&self) -> FactoryIdentity {
        FactoryIdentity { signer: self.factory, chain: vec![self.factory_certificate.clone()], caller: CALLER.into(), unattested: fieldseal_registration::domain::checks::UnattestedKeys::Refuse }
    }

    /// Builds the next bundle for `request.tenancy` over every port the world holds.
    pub fn build(&self, policy: &dyn Decide, request: &BuildRequest) -> Result<BuiltBundle, DistributionError> {
        self.build_with(policy, request, fieldseal_registration::domain::checks::UnattestedKeys::Refuse)
    }

    /// Like [`DemoWorld::build`], for a factory with the given allowance for unattested keys
    /// (REG-017): `AllowNonProduction` lets policy release rosters to a software device with a
    /// flag. The device's own attestation facts are never changed.
    pub fn build_with(&self, policy: &dyn Decide, request: &BuildRequest, unattested: fieldseal_registration::domain::checks::UnattestedKeys) -> Result<BuiltBundle, DistributionError> {
        self.build_sized(policy, request, unattested, usize::MAX)
    }

    /// Like [`DemoWorld::build_with`], with the bundle size limit lowered to `max_size`.
    pub fn build_sized(&self, policy: &dyn Decide, request: &BuildRequest, unattested: fieldseal_registration::domain::checks::UnattestedKeys, max_size: usize) -> Result<BuiltBundle, DistributionError> {
        let anchors = MemoryAnchorSource::new(AuthorityTime(self.next_anchor.load(Ordering::SeqCst)), &self.custody, self.receipt);
        let verifier = VerifyPublication::new(TrustStore::new(&self.trust), &self.publishing);
        let ports = FactoryPorts {
            registry: &self.registry,
            artefacts: &self.artefacts,
            rosters: &self.rosters,
            profiles: &self.profiles,
            policy,
            anchors: &anchors,
            custody: &self.custody,
            random: &self.random,
            bundles: &self.bundles,
        };
        let mut identity = self.identity();
        identity.unattested = unattested;
        let built = BundleBuilder::new(ports, &verifier, identity).with_max_size(max_size).build(request)?;
        self.next_anchor.store(built.manifest.issued.0 + AuthorityTime::SECOND, Ordering::SeqCst);
        Ok(built)
    }

    /// Adds the keys an online factory and an intake endpoint need, which a bundle-only world
    /// has no use for: a `registration` sealing key (X25519) that devices seal requests to, a
    /// `receiver` key (P-256) that answers upload challenges, and the runtime builds a
    /// software attestation verifier accepts (`app_ids`). They are certified under the root
    /// and [`DemoWorld::trust`] becomes its successor carrying them. Nothing generated for
    /// the world before this call changes, so earlier seeds keep their bytes.
    pub fn add_edge_services(&mut self, app_ids: &[&str]) -> Result<EdgeServices, String> {
        let a = Authority::new(&self.custody, CALLER);
        let sealing = self.custody.generate(KeyRole::Purpose(Purpose::Registration), KeyAlgorithm::X25519).map_err(err)?;
        let receiver = self.custody.generate(KeyRole::Purpose(Purpose::Receiver), KeyAlgorithm::P256).map_err(err)?;
        let terms = |purpose, serial| IssueTerms {
            purpose,
            record: None,
            not_before: self.t0,
            not_after: AuthorityTime(self.t0.0 + 300 * AuthorityTime::DAY),
            serial,
        };
        let sealing_certificate = a.issue(&self.root, &a.request(&sealing.id, Some(Purpose::Registration)).map_err(err)?, terms(Purpose::Registration, 100)).map_err(err)?;
        let receiver_certificate = a.issue(&self.root, &a.request(&receiver.id, Some(Purpose::Receiver)).map_err(err)?, terms(Purpose::Receiver, 101)).map_err(err)?;
        let mut contents = self.trust.contents().clone();
        contents.version = BundleVersion::parse("1.0.1").map_err(err)?;
        contents.issued = self.now;
        contents.certificates.push(sealing_certificate.clone());
        contents.certificates.push(receiver_certificate.clone());
        contents.runtime_builds = app_ids
            .iter()
            .map(|id| RuntimeBuild { platform: "software".into(), app_id: (*id).to_owned(), signing_digests: vec![sha256(id.as_bytes())] })
            .collect();
        self.trust = a.build_bundle(contents, &[&self.root], Some(&self.trust)).map_err(err)?;
        Ok(EdgeServices { sealing, receiver: receiver.id, receiver_certificate })
    }

    /// A trust bundle that is a valid successor of [`DemoWorld::trust`] (TRU-033).
    pub fn successor_trust(&self) -> Result<TrustBundle, String> {
        let mut contents = self.trust.contents().clone();
        contents.version = BundleVersion::parse("1.1.0").map_err(err)?;
        contents.issued = self.now;
        Authority::new(&self.custody, CALLER).build_bundle(contents, &[&self.root], Some(&self.trust)).map_err(err)
    }

    /// A trust bundle that is not a successor: an earlier version (TRU-033).
    pub fn predecessor_trust(&self) -> Result<TrustBundle, String> {
        let mut contents = self.trust.contents().clone();
        contents.version = BundleVersion::parse("0.9.0").map_err(err)?;
        Authority::new(&self.custody, CALLER).build_bundle(contents, &[&self.root], None).map_err(err)
    }
}
