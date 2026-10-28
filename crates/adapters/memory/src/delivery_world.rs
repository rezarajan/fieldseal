//! A bench that puts a simulated device and an intake in one process, for the delivery
//! tests and for `fieldseal device simulate`'s export and upload steps.
//!
//! The device is the collection simulator ([`SimulatedDevice`]); its records are sealed to
//! the practice authority's record key, so the real intake gate can open them. Intake is the
//! practice authority's keys behind the in-memory ports. Software keys throughout, never
//! attested.

use std::collections::BTreeMap;

use fieldseal_collection::application::Provisioning;
use fieldseal_collection::domain::WindowId;
use fieldseal_collection::domain::bundle::{HeldRoster, OpenedBundle, RegistrationGrant};
use fieldseal_instrument::domain::Instrument;
use fieldseal_intake::domain::{IssuedConsent, IssuedRoster, TenancyView};
use fieldseal_intake::gate::IntakeService;
use fieldseal_intake::upload::UploadService;
use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{Fingerprint, TenancyHandle, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, cbor};
use fieldseal_distribution::domain::ConsentState;
use fieldseal_intake::wire::CertWindow;
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::effective_default;

use crate::collection::{BundleSpec, SIMULATION_T0, SimulatedAuthority, SimulatedDevice};
use crate::delivery::{MemoryPopLedger, MemoryRegistrationRecords};
use crate::intake::practice::{PracticeAuthority, at};
use crate::intake::{MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore, MemoryTenancyRegistry};
use crate::policy::BuiltInPolicyEngine;
use crate::trust::SeededRandom;

/// What the bench learned about a device once it enrolled.
#[derive(Clone, Debug)]
pub struct Enrolled {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The export handle.
    pub handle: TenancyHandle,
    /// The signing public key.
    pub sign_pub: P256PublicKey,
    /// The instrument's fingerprint, as published.
    pub fingerprint: Fingerprint,
    /// The cohorts certified (each at generation 1).
    pub cohorts: Vec<String>,
    /// The rosters the device holds.
    pub rosters: Vec<HeldRoster>,
}

/// What a device is enrolled with: its instrument and layouts, rosters, and the cohorts the
/// tenancy certificate names (each at generation 1).
pub struct Enrolment<'a> {
    /// The instrument document.
    pub instrument: &'a Value,
    /// Layout documents.
    pub layouts: &'a [Value],
    /// The rosters held.
    pub rosters: Vec<HeldRoster>,
    /// The certified cohorts.
    pub cohorts: &'a [&'a str],
}

/// A simulated authority, a simulated device and the practice intake keys.
pub struct Bench {
    /// Publishes instruments and bundles for the device.
    pub sim: SimulatedAuthority,
    /// The intake side's keys: record, receipt, receiver, registration.
    pub practice: PracticeAuthority,
    /// The device's ports.
    pub device: SimulatedDevice,
    /// The windows the shell shows.
    pub windows: Vec<WindowId>,
    /// The registration documents a manifest carries.
    pub records: MemoryRegistrationRecords,
}

impl Bench {
    /// A bench whose devices and authorities derive from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            sim: SimulatedAuthority::new(seed),
            practice: PracticeAuthority::new(seed),
            device: SimulatedDevice::new(seed + 100),
            windows: vec![WindowId("capture".into()), WindowId("review".into()), WindowId("delivery".into())],
            records: MemoryRegistrationRecords::new(),
        }
    }

    /// What device provisioning gives the runtime: the publications' trust, and the practice
    /// record key as the provisional key records are sealed to.
    pub fn provisioning(&self) -> Provisioning<'_> {
        Provisioning {
            trust: &self.sim.trust,
            publishing: &self.sim.policy,
            build_anchor: sha256(b"fieldseal.dev/simulator/build/v1"),
            provisional_record_key: self.record_key(),
            windows: &self.windows,
        }
    }

    /// The practice authority's record key (`fs1-x`).
    pub fn record_key(&self) -> [u8; 32] {
        self.practice.record_key.public_key.encoded().try_into().expect("an X25519 key is 32 bytes")
    }

    /// The tenancy certificate and the bundle that registers the device: a bundle from the
    /// simulated authority whose grant names the practice record key, plus the certificate
    /// the practice registration key signs for the device's tenancy.
    pub fn registration(&self, tenancy: TenancyId, handle: TenancyHandle, sign_pub: &P256PublicKey, spec: Enrolment<'_>) -> Result<(OpenedBundle, Fingerprint), String> {
        let Enrolment { instrument, layouts, rosters, cohorts } = spec;
        let mut bundle = self.sim.bundle(tenancy, BundleSpec { instrument, layouts, rosters, register: true, issued_day: 15, seq: 1 })?;
        let fingerprint = bundle.instrument.artefact.fingerprint().ok_or("an instrument has a fingerprint")?;
        let certified: Vec<(&str, u64)> = cohorts.iter().map(|c| (*c, 1)).collect();
        let certificate = self.practice.tenancy_certificate_for(tenancy, handle, sign_pub.clone(), window(), &certified);
        let encoded = cbor::encode(&certificate.to_value()).map_err(|e| e.to_string())?;
        bundle.registration = Some(RegistrationGrant {
            certificate: sha256(&encoded),
            record_key: self.record_key(),
            period: self.practice.record_key.id,
            handle,
            not_before: SIMULATION_T0,
            not_after: AuthorityTime(SIMULATION_T0.0 + 365 * AuthorityTime::DAY),
            document: Some(certificate.to_value()),
        });
                Ok((bundle, fingerprint))
    }

    /// Opens a record payload the way intake does, with the practice record key.
    pub fn open_payload(&self, sealed: &fieldseal_kernel::seal::SealedBox) -> Result<fieldseal_collection::domain::payload::Payload, fieldseal_kernel::WireError> {
        use fieldseal_kernel::crypto::{Purpose, tags};
        use fieldseal_trust::ports::KeyCustody;
        let plain = self
            .practice
            .custody
            .open(&sealed.recipient, Purpose::Record, &tags::RECORD_SEAL, sealed, "bench")
            .map_err(|_| fieldseal_kernel::WireError::new(fieldseal_kernel::ErrorCode::Decrypt, 0, "the practice record key cannot open the record"))?;
        fieldseal_collection::domain::payload::Payload::from_value(cbor::decode(&plain)?)
    }

    /// The intake side for one enrolled device: the gate's ports with the tenancy registered,
    /// its rosters issued and the instrument published.
    pub fn intake(&self, enrolled: &Enrolled, instrument: Instrument) -> IntakeSide {
        let views = vec![TenancyView::new(enrolled.tenancy, enrolled.handle, vec![enrolled.sign_pub.clone()])];
        let instruments = MemoryInstrumentSource::new();
        instruments.add(enrolled.fingerprint, instrument);
        let rosters = MemoryRosterHistory::new();
        for r in &enrolled.rosters {
            rosters.record(
                enrolled.tenancy,
                IssuedRoster {
                    cohort: r.cohort.clone(),
                    version: r.version,
                    address: r.address,
                    issued_at: at(1),
                    consent: r
                        .subjects
                        .iter()
                        .map(|s| {
                            (
                                s.subject.clone(),
                                match s.consent {
                                    ConsentState::Granted => IssuedConsent::Granted,
                                    ConsentState::Refused => IssuedConsent::Refused,
                                    ConsentState::Unknown => IssuedConsent::Unknown,
                                },
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                },
            );
        }
        IntakeSide {
            store: MemorySubmissionStore::new(),
            registry: MemoryTenancyRegistry::new(views),
            rosters,
            instruments,
            platform: MemoryDataPlatform::new(),
            engine: BuiltInPolicyEngine,
            effective: effective_default(),
            random: SeededRandom::new(99),
            ledger: MemoryPopLedger::new(),
        }
    }
}

/// The certified collection window every bench tenancy gets.
pub fn window() -> CertWindow {
    CertWindow { not_before: at(0), not_after: at(100), grace: 30 * AuthorityTime::DAY }
}

/// Intake's in-memory ports for one enrolled device. [`IntakeSide::service`] builds the gate
/// over them, using the bench's practice keys.
pub struct IntakeSide {
    /// Raw submissions.
    pub store: MemorySubmissionStore,
    /// The registered tenancies.
    pub registry: MemoryTenancyRegistry,
    /// Issued rosters.
    pub rosters: MemoryRosterHistory,
    /// Published instruments.
    pub instruments: MemoryInstrumentSource,
    /// Where landed data goes.
    pub platform: MemoryDataPlatform,
    /// The policy engine.
    pub engine: BuiltInPolicyEngine,
    /// The effective intake policy.
    pub effective: EffectivePolicy,
    /// Randomness for consent sampling.
    pub random: SeededRandom,
    /// Replay protection for tokens.
    pub ledger: MemoryPopLedger,
}

impl IntakeSide {
    /// The verification gate over these ports and the bench's keys.
    pub fn service<'a>(&'a self, practice: &'a PracticeAuthority) -> IntakeService<'a> {
        IntakeService {
            store: &self.store,
            registry: &self.registry,
            rosters: &self.rosters,
            instruments: &self.instruments,
            platform: &self.platform,
            custody: &practice.custody,
            policy: &self.engine,
            effective: &self.effective,
            random: &self.random,
            trust: &practice.bundle,
            revocations: vec![],
            receipt_key: practice.receipt_key,
            caller: "intake-upload",
        }
    }

    /// The upload endpoint over `gate`, answering at `public_urls`.
    pub fn upload<'a>(&'a self, practice: &'a PracticeAuthority, gate: &'a IntakeService<'a>, public_urls: &'a [String]) -> UploadService<'a, 'a> {
        UploadService {
            intake: gate,
            ledger: &self.ledger,
            receiver_key: practice.receiver_key,
            receiver_certificate: &practice.receiver_certificate,
            public_urls,
        }
    }
}
