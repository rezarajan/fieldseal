//! The in-memory adapters' contract suites as a catalogue (issue #57).
//!
//! Each [`ContractCase`] runs one contract function from a context's `contract` module
//! against one adapter. The catalogue is what `fieldseal conformance run --suite contracts`
//! executes, and what `docs/reference/conformance.md` is generated from. A case panics when
//! the adapter breaks the contract, so a runner that must survive a failure runs each case
//! in its own process.

use std::collections::BTreeMap;

use fieldseal_collection::contract as col;
use fieldseal_collection::domain::Restriction;
use fieldseal_collection::domain::bundle::OpenedBundle;
use fieldseal_deployment::contract as dep;
use fieldseal_deployment::domain::SecretRef;
use fieldseal_distribution::contract as dis;
use fieldseal_distribution::domain::{ConsentState, Roster, RosterEntry, RuntimeProfile};
use fieldseal_instrument::domain::SchemaVersion;
use fieldseal_intake::contract as int;
use fieldseal_kernel::id::{CohortId, Digest, Generation, Seq, SubjectId, TenancyHandle, TenancyId};
use fieldseal_kernel::seal::{RecipientKey, RecipientSecret, Suite, seal_with_context};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::contract as pol;
use fieldseal_publishing::contract as publishing;
use fieldseal_publishing::contract::RecordingTransport;
use fieldseal_publishing::domain::{ArtefactKind, RevisionId, SourceSnapshot};
use fieldseal_registration::contract as reg;
use fieldseal_trust::contract as tru;
use fieldseal_trust::domain::{DeviceKeyKind, KeyProtection};
use fieldseal_trust::ports::{Attestor, SecureKeyStore, SourceRng};

use crate::collection::{
    MemoryCamera, MemoryDevicePolicy, MemoryElapsedClock, MemoryFileSource, MemorySecureDisplay, MemorySecureStorage, MemoryWallClock,
    SIMULATION_T0, SimulatedAuthority, SimulatedKeyStore, ToyCloseAuthority, ToyMemoryHardHash, ToyReceiptAuthority,
};
use crate::collection::{LocalTransport, MemoryBundleOpener};
use crate::delivery::{MemoryFileAccess, MemoryPrivateStorage, MemoryQrScanner, MemoryRegistrationRecords, MemoryShareTarget};
use crate::deployment::{MemoryBuildRegistry, MemoryDocumentationSink, MemorySecretStore};
use crate::distribution::{
    ClockAnchorSource, MemoryAnchorSource, MemoryBundleStore, MemoryRosterSource, MemoryRuntimeProfiles, MemoryTrustStore, SoftwareAgreementKey,
};
use crate::instrument::FullCatalogue;
use crate::intake::{MemoryDataPlatform, MemoryRosterHistory, MemorySubmissionStore, MemoryTenancyRegistry};
use crate::policy::{BuiltInPolicyEngine, MemoryDecisionLog, MemoryPolicySource};
use crate::publishing::{
    AcceptingValidator, MemoryArtefactRegistry, MemoryReviewSystem, MemorySourceRepository, MemoryTransparencyLog, PassThroughBuilder,
};
use crate::registration::{
    MemoryFleetRegistry, MemoryIdentityProvider, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore,
};
use crate::trust::{
    FixedClock, MemoryKeyCustody, MemoryKeyHolderRegistry, MemoryRevocationSource, MemorySecureKeyStore, SeededRandom,
    SoftwareAttestationVerifier,
};

/// One contract function run against one adapter.
#[derive(Clone, Copy)]
pub struct ContractCase {
    /// The bounded context that owns the port.
    pub context: &'static str,
    /// The port.
    pub port: &'static str,
    /// The contract function (`contract.rs` of the context).
    pub contract: &'static str,
    /// The adapter it runs against.
    pub adapter: &'static str,
    /// The requirements the contract helps to verify.
    pub requirements: &'static [&'static str],
    /// Runs the contract; panics if the adapter breaks it.
    pub run: fn(),
}

macro_rules! case {
    ($ctx:literal, $port:literal, $contract:literal, $adapter:literal, [$($req:literal),*], $run:expr) => {
        ContractCase { context: $ctx, port: $port, contract: $contract, adapter: $adapter, requirements: &[$($req),*], run: $run }
    };
}

fn tenancy() -> TenancyId {
    TenancyId::from([1; 32])
}

/// Every contract case for the in-memory adapters.
pub fn contract_cases() -> Vec<ContractCase> {
    vec![
        // ---- trust
        case!("trust", "KeyCustody", "key_custody_contract", "MemoryKeyCustody", ["TRU-003", "TRU-011", "TRU-016"], || {
            let sender = SeededRandom::new(2);
            tru::key_custody_contract(|| MemoryKeyCustody::new(SeededRandom::new(1)), &mut SourceRng(&sender));
        }),
        case!("trust", "SecureKeyStore", "secure_key_store_contract", "MemorySecureKeyStore", [], || {
            tru::secure_key_store_contract(MemorySecureKeyStore::new);
        }),
        case!("trust", "SecureKeyStore", "secure_key_store_contract", "SimulatedKeyStore", [], || {
            tru::secure_key_store_contract(|| SimulatedKeyStore::new(1));
        }),
        case!("trust", "Attestor", "attestor_contract", "MemorySecureKeyStore", [], || {
            tru::attestor_contract(|| {
                let store = MemorySecureKeyStore::new();
                let (k, _) = store.generate(DeviceKeyKind::Signing, KeyProtection { unlocked_required: true }, None).expect("key");
                (store, k)
            });
        }),
        case!("trust", "AttestationVerifier", "attestation_verifier_contract", "SoftwareAttestationVerifier", ["TRU-061"], || {
            tru::attestation_verifier_contract(|| {
                let store = MemorySecureKeyStore::new();
                let challenge = fieldseal_kernel::id::Nonce::from([5; 32]);
                let protection = KeyProtection { unlocked_required: true };
                let (k, public) = store.generate(DeviceKeyKind::Signing, protection, Some(challenge)).expect("key");
                let (_, other) = store.generate(DeviceKeyKind::Signing, protection, None).expect("other key");
                tru::VerifierFixture {
                    verifier: SoftwareAttestationVerifier,
                    evidence: store.evidence(&k).expect("evidence"),
                    challenge,
                    key: public.expect("public"),
                    other_key: other.expect("other public"),
                    roots: Vec::new(),
                }
            });
        }),
        case!("trust", "RevocationSource", "revocation_source_contract", "MemoryRevocationSource", ["TRU-040"], || {
            tru::revocation_source_contract(|| MemoryRevocationSource::new(AuthorityTime(1_700_000_000)));
        }),
        case!("trust", "AuthorityClock", "authority_clock_contract", "FixedClock", [], || {
            tru::authority_clock_contract(|| FixedClock::new(AuthorityTime(1_700_000_000)));
        }),
        case!("trust", "RandomSource", "random_source_contract", "SeededRandom", [], || {
            tru::random_source_contract(|| SeededRandom::new(42));
        }),
        case!("trust", "KeyHolderRegistry", "key_holder_registry_contract", "MemoryKeyHolderRegistry", ["TRU-092"], || {
            tru::key_holder_registry_contract(MemoryKeyHolderRegistry::new);
        }),
        // ---- policy
        case!("policy", "PolicyEngine", "policy_engine_contract", "BuiltInPolicyEngine", ["POL-034"], || {
            pol::policy_engine_contract(|| BuiltInPolicyEngine);
        }),
        case!("policy", "PolicySource", "policy_source_contract", "MemoryPolicySource", [], || {
            pol::policy_source_contract(MemoryPolicySource::new);
        }),
        case!("policy", "DecisionLog", "decision_log_contract", "MemoryDecisionLog", [], || {
            pol::decision_log_contract(MemoryDecisionLog::new);
        }),
        // ---- instrument
        case!("instrument", "ControlCatalogue", "control_catalogue_contract", "FullCatalogue", [], || {
            fieldseal_instrument::contract::control_catalogue_contract(|| FullCatalogue);
        }),
        // ---- publishing
        case!("publishing", "SourceRepository", "source_repository_contract", "MemorySourceRepository", ["PUB-002"], || {
            publishing::source_repository_contract(|| {
                let repo = MemorySourceRepository::new();
                let revision = RevisionId("abc123".into());
                repo.add(SourceSnapshot {
                    revision: revision.clone(),
                    author: fieldseal_kernel::id::ReviewerId::new("author").expect("id"),
                    document: b"doc".to_vec(),
                });
                (repo, revision)
            });
        }),
        case!("publishing", "ReviewSystem", "review_system_contract", "MemoryReviewSystem", ["PUB-013"], || {
            publishing::review_system_contract(MemoryReviewSystem::new);
        }),
        case!("publishing", "Builder", "builder_contract", "PassThroughBuilder", ["PUB-022"], || {
            publishing::builder_contract(|| {
                let snapshot = SourceSnapshot {
                    revision: RevisionId("r".into()),
                    author: fieldseal_kernel::id::ReviewerId::new("a").expect("id"),
                    document: b"doc".to_vec(),
                };
                (PassThroughBuilder::new("memory-builder"), snapshot)
            });
        }),
        case!("publishing", "ArtefactValidator", "artefact_validator_contract", "AcceptingValidator", ["PUB-003"], || {
            let artefact = publishing::sample_publication("health-check", "1.0.0", b"bytes").artefact;
            publishing::artefact_validator_contract(|| AcceptingValidator, &artefact);
        }),
        case!("publishing", "LogTransport", "log_transport_contract", "RecordingTransport", ["PUB-104"], || {
            publishing::log_transport_contract(RecordingTransport::new);
        }),
        case!("publishing", "LogTransport", "log_transport_contract", "LocalTransport", ["PUB-104"], || {
            publishing::log_transport_contract(|| LocalTransport);
        }),
        case!("publishing", "TransparencyLog", "transparency_log_contract", "MemoryTransparencyLog", ["PUB-102", "PUB-104", "PUB-105", "PUB-106"], || {
            let pin = MemoryTransparencyLog::new("memory.log", RecordingTransport::new()).pin();
            publishing::transparency_log_contract(RecordingTransport::new(), |t| MemoryTransparencyLog::new("memory.log", t), &pin);
        }),
        case!("publishing", "ArtefactRegistry", "artefact_registry_contract", "MemoryArtefactRegistry", ["PUB-060", "PUB-062"], || {
            publishing::artefact_registry_contract(MemoryArtefactRegistry::new);
        }),
        // ---- registration
        case!("registration", "RegistryStore", "registry_store_contract", "MemoryRegistryStore", ["REG-005", "REG-006"], || {
            reg::registry_store_contract(MemoryRegistryStore::new);
        }),
        case!("registration", "IdentityProvider", "identity_provider_contract", "MemoryIdentityProvider", ["REG-002"], || {
            let idp = MemoryIdentityProvider::new();
            idp.add("alice", "sub-alice", &["collector"], &["hwk", "user"], fieldseal_registration::domain::MethodAssurance::FromProvider);
            idp.set_default(Some("alice"));
            reg::identity_provider_contract(
                &idp,
                "https://portal.example/callback",
                |start| {
                    let query = start.redirect_to.split_once('?').expect("query").1;
                    query.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_owned(), v.to_owned())).collect()
                },
                true,
            );
        }),
        case!("registration", "ReceivedProgress", "received_progress_contract", "MemoryReceivedProgress", [], || {
            let p = MemoryReceivedProgress::new();
            p.received(tenancy(), Seq(4));
            p.received(tenancy(), Seq(2));
            reg::received_progress_contract(&p, &tenancy(), Seq(4));
        }),
        case!("registration", "FleetRegistry", "fleet_registry_contract", "MemoryFleetRegistry", ["REG-016"], || {
            reg::fleet_registry_contract(
                || {
                    let fleet = MemoryFleetRegistry::new();
                    fleet.add("SN-0001");
                    fleet
                },
                "SN-0001",
            );
        }),
        case!("registration", "Notifier", "notifier_contract", "MemoryNotifier", [], || {
            reg::notifier_contract(MemoryNotifier::new);
        }),
        // ---- distribution
        case!("distribution", "RosterSource", "roster_source_contract", "MemoryRosterSource", [], || {
            dis::roster_source_contract(
                || {
                    let s = MemoryRosterSource::new();
                    s.assign(
                        tenancy(),
                        vec![Roster {
                            cohort: CohortId::new("c1").expect("id"),
                            version: 1,
                            generation: Generation(1),
                            entries: vec![RosterEntry {
                                ordinal: 1,
                                subject: SubjectId::new("s1").expect("id"),
                                display: "One".into(),
                                attributes: BTreeMap::new(),
                                consent: ConsentState::Unknown,
                                prior_status: None,
                            }],
                            consent_covers: vec![],
                        }],
                    );
                    s
                },
                tenancy(),
            );
        }),
        case!("distribution", "AnchorSource", "anchor_source_contract", "MemoryAnchorSource", [], || {
            let w = crate::demo::DemoWorld::new(1, SIMULATION_T0).expect("world");
            dis::anchor_source_contract(
                || MemoryAnchorSource::new(w.now, &w.custody, w.receipt),
                |t| t.verify(&fieldseal_trust::domain::TrustStore::new(&w.trust)).is_ok(),
            );
        }),
        case!("distribution", "AnchorSource", "anchor_source_contract", "ClockAnchorSource", [], || {
            let w = crate::demo::DemoWorld::new(1, SIMULATION_T0).expect("world");
            let clock = crate::trust::FixedClock::new(w.now);
            dis::anchor_source_contract(
                || ClockAnchorSource::new(&clock, &w.custody, w.receipt),
                |t| t.verify(&fieldseal_trust::domain::TrustStore::new(&w.trust)).is_ok(),
            );
        }),
        case!("distribution", "TrustStore", "trust_store_contract", "MemoryTrustStore", [], || {
            let w = crate::demo::DemoWorld::new(1, SIMULATION_T0).expect("world");
            dis::trust_store_contract(
                MemoryTrustStore::new,
                w.trust.clone(),
                w.successor_trust().expect("successor"),
                w.predecessor_trust().expect("predecessor"),
            );
        }),
        case!("distribution", "BundleStore", "bundle_store_contract", "MemoryBundleStore", [], || {
            dis::bundle_store_contract(MemoryBundleStore::new);
        }),
        case!("distribution", "AgreementKey", "agreement_key_contract", "SoftwareAgreementKey", ["DIS-042"], || {
            let random = SeededRandom::new(7);
            let make = || {
                let secret = RecipientSecret::generate(Suite::Fs1P, &mut SourceRng(&SeededRandom::new(1)));
                let public = secret.public().expect("public");
                (SoftwareAgreementKey::new(secret).expect("key"), public)
            };
            let other = RecipientSecret::generate(Suite::Fs1P, &mut SourceRng(&SeededRandom::new(2))).public().expect("public");
            dis::agreement_key_contract(make, other, |to: &RecipientKey, tag, context, plaintext| {
                seal_with_context(&mut SourceRng(&random), to, tag, context, plaintext).expect("seals")
            });
        }),
        case!("distribution", "RuntimeProfiles", "runtime_profiles_contract", "MemoryRuntimeProfiles", [], || {
            let profile = RuntimeProfile { instrument_schema: SchemaVersion { major: 1, minor: 0, patch: 0 }, localisation_reference: None };
            dis::runtime_profiles_contract(
                || {
                    let p = MemoryRuntimeProfiles::new();
                    p.record(tenancy(), profile.clone());
                    p
                },
                tenancy(),
                profile.clone(),
            );
        }),
        // ---- collection
        case!("collection", "ElapsedClock", "elapsed_clock_contract", "MemoryElapsedClock", [], || {
            col::elapsed_clock_contract(MemoryElapsedClock::new);
        }),
        case!("collection", "SecureStorage", "secure_storage_contract", "MemorySecureStorage", ["COL-050"], || {
            col::secure_storage_contract(MemorySecureStorage::new);
        }),
        case!("collection", "SecureDisplay", "secure_display_contract", "MemorySecureDisplay", [], || {
            col::secure_display_contract(MemorySecureDisplay::new);
        }),
        case!("collection", "DevicePolicy", "device_policy_self_managed_contract", "MemoryDevicePolicy", ["PLAT-033"], || {
            col::device_policy_self_managed_contract(MemoryDevicePolicy::self_managed, |d, r| d.remove_out_of_band(r));
        }),
        case!("collection", "DevicePolicy", "device_policy_emm_contract", "MemoryDevicePolicy", ["PLAT-033"], || {
            col::device_policy_emm_contract(|| MemoryDevicePolicy::emm_managed(&Restriction::ALL), |d, r| d.remove_out_of_band(r));
        }),
        case!("collection", "Camera", "camera_contract", "MemoryCamera", [], || {
            col::camera_contract(|| MemoryCamera);
        }),
        case!("collection", "MemoryHardHash", "memory_hard_hash_contract", "ToyMemoryHardHash", [], || {
            col::memory_hard_hash_contract(|| ToyMemoryHardHash);
        }),
        case!("collection", "WallClock", "wall_clock_contract", "MemoryWallClock", [], || {
            col::wall_clock_contract(|| MemoryWallClock::at(SIMULATION_T0.0));
            col::wall_clock_contract(MemoryWallClock::default);
        }),
        case!("collection", "FileAccess", "file_access_contract", "MemoryFileSource", [], || {
            col::file_access_contract(MemoryFileSource::offering);
        }),
        case!("collection", "SecureKeyStore", "record_signing_key_store_contract", "SimulatedKeyStore", [], || {
            col::record_signing_key_store_contract(|| SimulatedKeyStore::new(2), |k, l| k.set_locked(l));
        }),
        case!("collection", "BundleOpener", "bundle_opener_contract", "MemoryBundleOpener", ["DIS-042"], || {
            let authority = SimulatedAuthority::new(3);
            let opener = MemoryBundleOpener::new();
            let contents = OpenedBundle {
                address: Digest::from([7; 32]),
                tenancy: tenancy(),
                seq: 1,
                issued: SIMULATION_T0,
                registration: None,
                time_tokens: vec![],
                instruments: vec![authority
                    .publish(ArtefactKind::Policy, "sample-policy", "1.0.0", &fieldseal_kernel::cbor::map([("kind", fieldseal_kernel::Value::Text("Policy".into()))]))
                    .expect("publish")],
                layouts: vec![],
                policy: vec![],
                rosters: vec![],
                assignments: vec![],
                withdrawals: vec![],
            };
            let ours = opener.register(contents);
            col::bundle_opener_contract(|| &opener, &ours, b"FSB1 someone else's");
        }),
        case!("collection", "ReceiptCheck", "receipt_check_contract", "ToyReceiptAuthority", ["DEL-064"], || {
            let authority = ToyReceiptAuthority::new(b"a");
            let valid = authority.issue(tenancy(), Seq(5), Digest::from([2; 32]), AuthorityTime(10));
            let mut forged = valid.clone();
            forged.signature = fieldseal_kernel::crypto::Signature(vec![0; 32]);
            let untrusted = ToyReceiptAuthority::new(b"b").issue(tenancy(), Seq(5), Digest::from([2; 32]), AuthorityTime(10));
            col::receipt_check_contract(|| ToyReceiptAuthority::new(b"a"), valid, forged, untrusted);
        }),
        case!("collection", "CloseCertificateCheck", "close_certificate_check_contract", "ToyCloseAuthority", ["COL-007"], || {
            let authority = ToyCloseAuthority::new(b"a");
            let genuine = authority.issue(tenancy(), Seq(9), "lost");
            col::close_certificate_check_contract(&authority, &genuine, tenancy(), Seq(9));
        }),
        // ---- delivery
        case!("delivery", "FileAccess", "file_access_contract", "MemoryFileAccess", ["DEL-020"], || {
            use fieldseal_delivery::domain::DestinationClass;
            fieldseal_delivery::contract::file_access_contract(|| MemoryFileAccess::new(DestinationClass::Removable));
            fieldseal_delivery::contract::file_access_contract(|| MemoryFileAccess::new(DestinationClass::Cloud));
        }),
        case!("delivery", "ShareTarget", "share_target_contract", "MemoryShareTarget", [], || {
            use fieldseal_delivery::ports::ShareOutcome;
            fieldseal_delivery::contract::share_target_contract(|| MemoryShareTarget(ShareOutcome::Shared));
            fieldseal_delivery::contract::share_target_contract(|| MemoryShareTarget(ShareOutcome::Failed));
        }),
        case!("delivery", "PrivateStorage", "private_storage_contract", "MemoryPrivateStorage", [], || {
            fieldseal_delivery::contract::private_storage_contract(MemoryPrivateStorage::new);
        }),
        case!("delivery", "QrScanner", "qr_scanner_contract", "MemoryQrScanner", [], || {
            fieldseal_delivery::contract::qr_scanner_contract(|| {
                let q = MemoryQrScanner::default();
                q.queue(b"scanned".to_vec());
                q
            });
        }),
        case!("delivery", "RegistrationRecords", "registration_records_contract", "MemoryRegistrationRecords", [], || {
            let records = MemoryRegistrationRecords::new();
            records.set(
                tenancy(),
                fieldseal_delivery::ports::ManifestAttachments {
                    certificate: Some(fieldseal_kernel::cbor::map([("v", fieldseal_kernel::Value::Int(1))])),
                    registration: None,
                },
            );
            fieldseal_delivery::contract::registration_records_contract(&records, tenancy());
        }),
        case!("intake", "PopLedger", "pop_ledger_contract", "MemoryPopLedger", ["DEL-003"], || {
            int::pop_ledger_contract(crate::delivery::MemoryPopLedger::new);
        }),
        // ---- intake
        case!("intake", "SubmissionStore", "submission_store_contract", "MemorySubmissionStore", [], || {
            int::submission_store_contract(MemorySubmissionStore::new);
        }),
        case!("intake", "TenancyRegistry", "tenancy_registry_contract", "MemoryTenancyRegistry", [], || {
            let handle = TenancyHandle::from([1; 16]);
            int::tenancy_registry_contract(
                || MemoryTenancyRegistry::new(vec![fieldseal_intake::domain::TenancyView::new(tenancy(), handle, vec![])]),
                (tenancy(), handle),
            );
        }),
        case!("intake", "RosterHistory", "roster_history_contract", "MemoryRosterHistory", [], || {
            use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
            int::roster_history_contract(
                || {
                    let h = MemoryRosterHistory::new();
                    for (cohort, version) in [("b", 2), ("a", 1), ("b", 1)] {
                        h.record(
                            tenancy(),
                            IssuedRoster {
                                cohort: CohortId::new(cohort).expect("id"),
                                version,
                                address: Digest::from([version as u8; 32]),
                                issued_at: AuthorityTime(version),
                                consent: BTreeMap::from([(SubjectId::new("s").expect("id"), IssuedConsent::Unknown)]),
                                covers: Default::default(),
                            },
                        );
                    }
                    h
                },
                tenancy(),
            );
        }),
        case!("intake", "DataPlatform", "data_platform_contract", "MemoryDataPlatform", ["INT-011"], || {
            int::data_platform_contract(MemoryDataPlatform::new);
        }),
        // ---- deployment
        case!("deployment", "BuildRegistry", "build_registry_contract", "MemoryBuildRegistry", [], || {
            dep::build_registry_contract(MemoryBuildRegistry::new);
        }),
        case!("deployment", "SecretStore", "secret_store_contract", "MemorySecretStore", ["DEP-033"], || {
            let known = SecretRef("factory/db".into());
            dep::secret_store_contract(|| MemorySecretStore::new(BTreeMap::from([(known.clone(), b"s3cret".to_vec())])), known.clone());
        }),
        case!("deployment", "DocumentationSink", "documentation_sink_contract", "MemoryDocumentationSink", [], || {
            dep::documentation_sink_contract(MemoryDocumentationSink::new);
        }),
    ]
}
