//! `BuildBundle` (distribution §3): the factory builds, seals and signs the next bundle for
//! one tenancy.
//!
//! The steps, in order, each failing closed:
//! 1. the tenancy's state ([`super::release::check_state`], DIS-001, DIS-003, DIS-004);
//! 2. every requested artefact is fetched from the registry and verified in full, and none is
//!    withdrawn (DIS-011);
//! 3. the pieces fit each other and the runtime the tenancy registered with (DIS-012,
//!    DIS-016, DIS-017);
//! 4. rosters are taken from the source, matched to the tenancy's cohorts and generations
//!    (DIS-014) and cut to the fields the instruments reference (DIS-013);
//! 5. a fresh time token, then the release decision from policy (DIS-002);
//! 6. the policy layers behind the decision are included as publications (POL-050);
//! 7. the content is sealed to the tenancy's agreement key with the tenancy ID bound into
//!    the HPKE `info` (DIS-020), and the sealed envelope is signed with the factory key
//!    through `KeyCustody` (DIS-021);
//! 8. the file is encoded (WIRE-090), stored, and returned.

use std::collections::BTreeSet;

use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::id::{ContentAddress, KeyId, TenancyId};
use fieldseal_kernel::seal::{RecipientKey, seal_with_context};
use fieldseal_policy::application::Decide;
use fieldseal_policy::domain::LayerSelector;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::{ArtefactKind, Publication, PublishingError, Withdrawal};
use fieldseal_publishing::ports::ArtefactRegistry;
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::domain::TenancyRecord;
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::{DeviceKeyKind, KeyCertificate, KeyRole};
use fieldseal_trust::ports::{KeyCustody, RandomSource, SourceRng};
use zeroize::Zeroizing;

use super::release::{check_state, decide_release, release_facts};
use crate::domain::file::MAX_BUNDLE_FILE;
use crate::domain::{
    BundleContent, BundleFile, BundleManifest, BundleSeq, DistributionError, DistributionEvent, ReleaseDecision, Roster,
    SealedBundle, artefacts_of, check_composition,
};
use crate::ports::{AnchorSource, BundleStore, RosterSource, RuntimeProfiles};

/// What a build is for.
#[derive(Clone, PartialEq, Debug)]
pub struct BuildRequest {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The instruments to include, by fingerprint.
    pub instruments: Vec<ContentAddress>,
    /// The layouts factory policy assigns (DIS-016).
    pub layouts: Vec<ContentAddress>,
    /// The runtime UI localisations policy assigns (DIS-017).
    pub localisations: Vec<ContentAddress>,
    /// Newer trust bundles to carry, as published `TrustBundle` artefacts.
    pub trust_updates: Vec<ContentAddress>,
    /// A practice bundle: no rosters (DIS-004).
    pub practice: bool,
    /// Which policy layers apply to this bundle's instruments.
    pub selector: LayerSelector,
}

impl BuildRequest {
    /// A request for `instruments` for `tenancy` with nothing else.
    pub fn new(tenancy: TenancyId, instruments: Vec<ContentAddress>) -> Self {
        Self {
            tenancy,
            instruments,
            layouts: vec![],
            localisations: vec![],
            trust_updates: vec![],
            practice: false,
            selector: LayerSelector::default(),
        }
    }
}

/// The ports `BuildBundle` drives (distribution §4).
#[derive(Clone, Copy)]
pub struct FactoryPorts<'a> {
    /// Tenancy state, keys, cohorts and certificates (`RegistryStore`, shared with Registration).
    pub registry: &'a dyn RegistryStore,
    /// Published artefacts and withdrawals (`ArtefactRegistry`).
    pub artefacts: &'a dyn ArtefactRegistry,
    /// Rosters for the tenancy's cohorts.
    pub rosters: &'a dyn RosterSource,
    /// What each runtime reported at registration.
    pub profiles: &'a dyn RuntimeProfiles,
    /// The release decision (`PolicyEngine` through `Decide`).
    pub policy: &'a dyn Decide,
    /// Authority time statements.
    pub anchors: &'a dyn AnchorSource,
    /// The factory signing key (`Signer`).
    pub custody: &'a dyn KeyCustody,
    /// Randomness for sealing.
    pub random: &'a dyn RandomSource,
    /// Bundles built so far, for the sequence number.
    pub bundles: &'a dyn BundleStore,
}

/// The factory's signing identity.
#[derive(Clone, Debug)]
pub struct FactoryIdentity {
    /// The factory signing key's ID.
    pub signer: KeyId,
    /// The signer's own certificate to present, or none when recipients' trust bundles pin it.
    pub chain: Vec<KeyCertificate>,
    /// The caller name recorded in the key-custody log.
    pub caller: String,
    /// Whether this factory runs with the non-production allowance for unattested keys
    /// (REG-017). It lets policy release rosters to a software device with a flag, never as if
    /// the device were attested. Production never sets it.
    pub unattested: UnattestedKeys,
}

/// A built bundle and the facts about its release.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BuiltBundle {
    /// The sealed, signed file, as stored.
    pub sealed: SealedBundle,
    /// What the bundle contains.
    pub manifest: BundleManifest,
    /// The release decision, naming the policy (DIS-002).
    pub decision: ReleaseDecision,
    /// The decision's index in the decision log.
    pub decision_log_index: u64,
    /// `BundleReleased`.
    pub event: DistributionEvent,
}

/// `BuildBundle`.
pub trait BuildBundle {
    /// Builds, seals and signs the next bundle.
    fn build(&self, request: &BuildRequest) -> Result<BuiltBundle, DistributionError>;
}

/// The bundle builder over its ports.
pub struct BundleBuilder<'a, 'v> {
    ports: FactoryPorts<'a>,
    verifier: &'a VerifyPublication<'v>,
    identity: FactoryIdentity,
    max_size: usize,
}

fn port<E: std::fmt::Display>(name: &'static str) -> impl FnOnce(E) -> DistributionError {
    move |e| DistributionError::Port { port: name, reason: e.to_string() }
}

impl<'a, 'v> BundleBuilder<'a, 'v> {
    /// A builder. `verifier` is a full publication verifier (provenance included, PUB-073): the
    /// factory re-verifies every artefact before it relies on it.
    pub fn new(ports: FactoryPorts<'a>, verifier: &'a VerifyPublication<'v>, identity: FactoryIdentity) -> Self {
        Self { ports, verifier, identity, max_size: MAX_BUNDLE_FILE }
    }

    /// Lowers the size limit below the wire's 64 MiB (distribution open question 2).
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size.min(MAX_BUNDLE_FILE);
        self
    }

    fn fetch(&self, address: &ContentAddress, kind: ArtefactKind, withdrawals: &[Withdrawal]) -> Result<Publication, DistributionError> {
        let not_published = |reason: String| DistributionError::ArtefactNotPublished { address: *address, reason };
        let publication = self
            .ports
            .artefacts
            .get(address)
            .map_err(port("ArtefactRegistry"))?
            .ok_or_else(|| not_published("not in the registry".into()))?;
        if publication.artefact.kind() != kind {
            return Err(not_published(format!("it is a {}, not a {kind}", publication.artefact.kind())));
        }
        self.verifier.verify(&publication, withdrawals).map_err(|e| match e {
            PublishingError::Withdrawn => not_published("withdrawn".into()),
            other => not_published(other.to_string()),
        })?;
        Ok(publication)
    }

    fn fetch_all(&self, addresses: &[ContentAddress], kind: ArtefactKind, withdrawals: &[Withdrawal]) -> Result<Vec<Publication>, DistributionError> {
        let mut seen = BTreeSet::new();
        addresses
            .iter()
            .filter(|a| seen.insert(**a))
            .map(|a| self.fetch(a, kind, withdrawals))
            .collect()
    }

    fn rosters(&self, record: &TenancyRecord, referenced: &BTreeSet<String>) -> Result<Vec<Roster>, DistributionError> {
        let sourced = self.ports.rosters.current_rosters(&record.id).map_err(port("RosterSource"))?;
        let mut out: Vec<Roster> = Vec::new();
        for roster in sourced {
            let assigned = record.cohorts.iter().find(|c| c.cohort == roster.cohort).ok_or_else(|| DistributionError::Roster {
                cohort: roster.cohort.clone(),
                reason: "the cohort isn't assigned to the tenancy".into(),
            })?;
            if assigned.generation != roster.generation {
                return Err(DistributionError::Roster {
                    cohort: roster.cohort.clone(),
                    reason: format!("generation {} isn't the tenancy's generation {}", roster.generation.0, assigned.generation.0),
                });
            }
            if out.iter().any(|r| r.cohort == roster.cohort) {
                return Err(DistributionError::Roster { cohort: roster.cohort.clone(), reason: "two rosters for one cohort".into() });
            }
            out.push(roster.restricted_to(referenced));
        }
        for c in &record.cohorts {
            if !out.iter().any(|r| r.cohort == c.cohort) {
                return Err(DistributionError::Roster { cohort: c.cohort.clone(), reason: "no roster for an assigned cohort".into() });
            }
        }
        out.sort_by(|a, b| a.cohort.cmp(&b.cohort));
        Ok(out)
    }
}

impl BuildBundle for BundleBuilder<'_, '_> {
    fn build(&self, request: &BuildRequest) -> Result<BuiltBundle, DistributionError> {
        let p = &self.ports;
        // 1. The tenancy.
        let record = p.registry.tenancy(&request.tenancy).map_err(port("RegistryStore"))?.ok_or(DistributionError::NotRegistered)?;
        check_state(record.state, request.practice)?;
        let agreement = record.active_key(DeviceKeyKind::Agreement).ok_or(DistributionError::NotRegistered)?.public_key.clone();
        let profile = p
            .profiles
            .profile(&request.tenancy)
            .map_err(port("RuntimeProfiles"))?
            .ok_or_else(|| DistributionError::Withheld(vec!["runtime-profile-unknown".into()]))?;

        // 2. Published, verified, not withdrawn artefacts only.
        let withdrawals = p.artefacts.withdrawals().map_err(port("ArtefactRegistry"))?;
        if request.instruments.is_empty() {
            return Err(DistributionError::Withheld(vec!["no-instruments".into()]));
        }
        let instruments = self.fetch_all(&request.instruments, ArtefactKind::Instrument, &withdrawals)?;
        let layouts = self.fetch_all(&request.layouts, ArtefactKind::Layout, &withdrawals)?;
        let localisations = self.fetch_all(&request.localisations, ArtefactKind::Localisation, &withdrawals)?;
        let trust_updates = self.fetch_all(&request.trust_updates, ArtefactKind::TrustBundle, &withdrawals)?;

        // 3. The pieces fit each other and the runtime.
        let referenced = check_composition(&artefacts_of(&instruments), &artefacts_of(&layouts), &artefacts_of(&localisations), &profile)?;

        // 4. Rosters.
        let rosters = if request.practice { Vec::new() } else { self.rosters(&record, &referenced)? };
        let certificate = if request.practice { None } else { record.certificate.clone() };
        if !request.practice && certificate.is_none() {
            return Err(DistributionError::NotRegistered);
        }

        // 5. Time, then the release decision.
        let time_token = p.anchors.time_token().map_err(port("AnchorSource"))?;
        let mut active = 0;
        for c in &record.cohorts {
            active = active.max(p.rosters.active_tenancies(&c.cohort, &record.id).map_err(port("RosterSource"))?);
        }
        let facts = release_facts(&record, !rosters.is_empty(), active, self.identity.unattested == UnattestedKeys::AllowNonProduction);
        let released = decide_release(p.policy, &request.selector, request.tenancy, facts, time_token.authority_time)?;
        let ReleaseDecision::Release { policy: layers } = &released.decision else {
            unreachable!("decide_release returns Err for a withhold");
        };

        // 6. The runtime policy as publications (POL-050).
        let policy = self.fetch_all(layers, ArtefactKind::Policy, &withdrawals)?;

        // 7. Assemble, seal, sign.
        let seq = match p.bundles.latest(&request.tenancy).map_err(port("BundleStore"))? {
            Some(held) => BundleSeq(held.seq.0 + 1),
            None => BundleSeq(1),
        };
        let content = BundleContent {
            tenancy: request.tenancy,
            seq,
            issued: time_token.authority_time,
            certificate,
            time_token,
            instruments,
            layouts,
            localisations,
            policy,
            rosters,
            trust_updates,
            withdrawals,
        };
        let plaintext = Zeroizing::new(content.encode().map_err(DistributionError::Wire)?);
        // The sealed file is larger than its plaintext: refuse before sealing or signing what
        // could never be stored.
        if plaintext.len() > self.max_size {
            return Err(DistributionError::TooLarge { size: plaintext.len(), limit: self.max_size });
        }
        let sealed = seal_with_context(
            &mut SourceRng(p.random),
            &RecipientKey::P256(agreement),
            &tags::BUNDLE_SEAL,
            request.tenancy.as_bytes(),
            &plaintext,
        )
        .map_err(DistributionError::Wire)?;
        // The envelope and its signer are known before the signature: check the size here, so a
        // bundle that is too large costs no signature (the key-custody log records every use).
        let unsigned = BundleFile::signed_structure(&sealed, &self.identity.signer);
        let unsigned_size = fieldseal_kernel::cbor::encode(&unsigned).map_or(usize::MAX, |b| b.len());
        if unsigned_size > self.max_size {
            return Err(DistributionError::TooLarge { size: unsigned_size, limit: self.max_size });
        }
        let sig = p
            .custody
            .sign(
                &self.identity.signer,
                KeyRole::Purpose(Purpose::Factory),
                &tags::BUNDLE,
                &BundleFile::signed_structure(&sealed, &self.identity.signer),
                &self.identity.caller,
            )
            .map_err(port("KeyCustody"))?;
        let file = BundleFile { sealed, signer: self.identity.signer, chain: self.identity.chain.clone(), sig };

        // 8. The file.
        let bytes = file.encode();
        if bytes.len() > self.max_size {
            return Err(DistributionError::TooLarge { size: bytes.len(), limit: self.max_size });
        }
        let bundle = SealedBundle::new(request.tenancy, seq, content.issued, bytes);
        p.bundles.put(&bundle).map_err(port("BundleStore"))?;
        Ok(BuiltBundle {
            event: DistributionEvent::BundleReleased { tenancy: request.tenancy, bundle: bundle.address, policy: layers.clone() },
            manifest: content.manifest(),
            decision_log_index: released.log_index,
            decision: released.decision,
            sealed: bundle,
        })
    }
}
