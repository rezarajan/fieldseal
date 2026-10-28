//! `VerifyBundle` and `ImportBundle`: what a runtime does with a bundle from any route
//! (DIS-030, DIS-031, DIS-060; WIRE-093).
//!
//! The order is fixed and the first failure stops everything, so nothing from a bad bundle
//! is used:
//!
//! 1. **Size and envelope.** The file is checked against the size limit before anything else
//!    is read, then parsed with bounded, canonical decoding.
//! 2. **Recipient, signer, chain, signature.** The seal must name this tenancy's agreement key
//!    (DIS-030 step 2); then the factory signature over the sealed envelope, chained to the
//!    trust bundle, before the seal is opened (WIRE-093).
//! 3. **Open.** Through the agreement key; the tenancy ID is bound into the HPKE `info`, so a
//!    bundle sealed for another tenancy does not open.
//! 4. **Contents.** Strict decoding; the tenancy, certificate, agreement key and time token
//!    agree with each other and with the trust bundle.
//! 5. **Sequence.** Greater than the last one held.
//! 6. **Artefacts.** Each publication verifies with Publishing's verifier (the provenance
//!    only has to describe the artefact, PUB-073); instruments match their fingerprints
//!    (INS-103); nothing is on the withdrawal list; trust updates are valid successors;
//!    policy passes the invariant floors (POL-051).
//! 7. **Compatibility.** Schema versions, layouts and localisations (DIS-012, DIS-016,
//!    DIS-017).
//! 8. **Rosters.** Only referenced fields (DIS-013), the certificate's generations (DIS-014),
//!    and no version or generation lower than held.

use std::collections::BTreeSet;

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::digest::key_id;
use fieldseal_kernel::error::ErrorCode;
use fieldseal_kernel::id::{CohortId, ContentAddress, Generation, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{AppliedVersions, PolicyDocument, PublishingPolicy, RuntimeEvaluator, decode_document};
use fieldseal_publishing::application::{ProvenanceCheck, VerifyPublication};
use fieldseal_publishing::domain::{ArtefactKind, Publication, PublishingError, artefact_address};
use fieldseal_trust::domain::{TrustBundle, TrustStore};

use crate::domain::{
    check_publication_tree_head_age, BundleContent, BundleFile, BundleManifest, BundleRejection, BundleSeq, CompositionError, Roster, RuntimeProfile, SealedBundle,
    check_composition, artefacts_of,
};
use crate::ports::{AgreementError, AgreementKey, BundleStore, BundleStoreError};

/// A roster the runtime already holds, by version and generation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeldRoster {
    /// The cohort.
    pub cohort: CohortId,
    /// The version held.
    pub version: u64,
    /// The generation held.
    pub generation: Generation,
}

/// What the runtime already holds, which a new bundle must not go back on.
#[derive(Clone, Debug, Default)]
pub struct HeldState {
    /// The sequence number of the bundle held, if any.
    pub seq: Option<BundleSeq>,
    /// The rosters held.
    pub rosters: Vec<HeldRoster>,
    /// The highest policy version applied per layer and name (POL-052).
    pub policies: AppliedVersions,
    /// Publications from earlier bundles, against which a withdrawal for an artefact not in
    /// this bundle can be checked.
    pub publications: Vec<Publication>,
}

/// What an import needs to know about the runtime.
#[derive(Clone, Debug)]
pub struct ImportState {
    /// The active tenancy.
    pub tenancy: TenancyId,
    /// The runtime's current authority time: the latest anchor it holds. The factory
    /// signature must be valid at this time.
    pub now: AuthorityTime,
    /// What is already held.
    pub held: HeldState,
}

/// What the journal's `import` record names (WIRE-058).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportRecord {
    /// The bundle's content address.
    pub bundle: ContentAddress,
    /// Each artefact loaded.
    pub artefacts: Vec<ContentAddress>,
    /// Each roster version loaded, with the content address of its canonical encoding.
    pub rosters: Vec<(CohortId, u64, ContentAddress)>,
}

/// A bundle that passed every check, and what the runtime takes from it.
#[derive(Clone, PartialEq, Debug)]
pub struct VerifiedBundle {
    /// The bundle's content address.
    pub address: ContentAddress,
    /// What it contains.
    pub manifest: BundleManifest,
    /// The contents. The runtime opens them only inside a session (DIS-033).
    pub content: BundleContent,
    /// Newer trust bundles it carries, each a valid successor of the one held (TRU-033). The
    /// runtime verifies them in the order given and replaces its trust bundle.
    pub trust_updates: Vec<TrustBundle>,
    /// The policy layers, outermost first, which passed the invariant floors (POL-051).
    pub policy: Vec<PolicyDocument>,
    /// Artefacts held from earlier bundles that a valid withdrawal in this one names.
    pub withdrawn: Vec<ContentAddress>,
}

impl VerifiedBundle {
    /// The facts the `anchor` and `import` journal records state (DIS-032, WIRE-057, WIRE-058).
    pub fn import_record(&self) -> ImportRecord {
        let c = &self.content;
        let artefacts = [&c.instruments, &c.layouts, &c.localisations, &c.policy, &c.trust_updates]
            .into_iter()
            .flatten()
            .map(|p| *p.address())
            .collect();
        let rosters = c.rosters.iter().map(|r| (r.cohort.clone(), r.version, ContentAddress::of(&r.encode()))).collect();
        ImportRecord { bundle: self.address, artefacts, rosters }
    }
}

/// The verifier a runtime builds from what it already trusts.
pub struct VerifyBundle<'a> {
    trust: &'a TrustBundle,
    publishing: &'a PublishingPolicy,
    agreement: &'a dyn AgreementKey,
    profile: RuntimeProfile,
    max_size: usize,
}

impl<'a> VerifyBundle<'a> {
    /// A verifier against the runtime's `trust` bundle and publishing policy, opening with
    /// `agreement`, for a runtime that implements `profile`. The size limit starts at the
    /// wire's 64 MiB.
    pub fn new(trust: &'a TrustBundle, publishing: &'a PublishingPolicy, agreement: &'a dyn AgreementKey, profile: RuntimeProfile) -> Self {
        Self { trust, publishing, agreement, profile, max_size: crate::domain::MAX_BUNDLE_FILE }
    }

    /// Lowers the size limit (the runtime policy's limit).
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size.min(crate::domain::MAX_BUNDLE_FILE);
        self
    }

    /// Verifies `bytes` in the order of DIS-030, stopping at the first failure.
    pub fn verify(&self, bytes: &[u8], state: &ImportState) -> Result<VerifiedBundle, BundleRejection> {
        // 1. Size, then a well-formed envelope.
        let file = BundleFile::decode(bytes, self.max_size).map_err(|e| match e.code {
            ErrorCode::Size => BundleRejection::TooLarge { size: bytes.len(), limit: self.max_size },
            _ => BundleRejection::Malformed(e),
        })?;

        // 2. The seal must name this tenancy's agreement key (an outer field, checked before
        // anything is trusted), then signer, chain and signature, before the seal is opened.
        if file.sealed.recipient != self.agreement.key_id() {
            return Err(BundleRejection::WrongRecipient);
        }
        let store = TrustStore::new(self.trust);
        store
            .verify_signature(&file.signer, &file.chain, &tags::BUNDLE, &file.structure(), &file.sig, state.now)
            .map_err(BundleRejection::Signature)?;

        // 3. Open, with the tenancy bound in.
        let plaintext = self
            .agreement
            .open(&tags::BUNDLE_SEAL, state.tenancy.as_bytes(), &file.sealed)
            .map_err(|e| match e {
                AgreementError::WrongRecipient => BundleRejection::WrongRecipient,
                AgreementError::Open(w) => BundleRejection::Open(w),
                AgreementError::Backend(_) => BundleRejection::Open(fieldseal_kernel::WireError::new(ErrorCode::Decrypt, 0, "key store failed")),
            })?;

        // 4. Contents.
        let content = BundleContent::decode(&plaintext).map_err(BundleRejection::Content)?;
        drop(plaintext);
        self.check_identity(&content, &file, state, &store)?;

        // 5. Sequence.
        if let Some(held) = state.held.seq
            && content.seq <= held
        {
            return Err(BundleRejection::NotNewer { held: held.0, offered: content.seq.0 });
        }

        // 6. Artefacts.
        let (trust_updates, policy, withdrawn) = self.check_artefacts(&content, state)?;
        // POL-052: a runtime policy never goes back to a lower version of a layer it applies.
        let mut applied = state.held.policies.clone();
        for document in &policy {
            applied.admit(document).map_err(|f| BundleRejection::Policy(f.message))?;
        }

        // 7. Compatibility, which also yields the roster fields the instruments reference.
        let referenced = check_composition(
            &artefacts_of(&content.instruments),
            &artefacts_of(&content.layouts),
            &artefacts_of(&content.localisations),
            &self.profile,
        )
        .map_err(BundleRejection::Composition)?;

        // 8. Rosters.
        check_rosters(&content, &referenced, &state.held)?;

        Ok(VerifiedBundle { address: ContentAddress::of(bytes), manifest: content.manifest(), content, trust_updates, policy, withdrawn })
    }

    fn check_identity(&self, content: &BundleContent, file: &BundleFile, state: &ImportState, store: &TrustStore<'_>) -> Result<(), BundleRejection> {
        let bad = |m: &str| BundleRejection::Certificate(m.to_owned());
        if content.tenancy != state.tenancy {
            return Err(BundleRejection::WrongTenancy);
        }
        match &content.certificate {
            Some(cert) => {
                cert.verify(self.trust).map_err(|e| BundleRejection::Certificate(format!("tenancy certificate: {e}")))?;
                if cert.tenancy != content.tenancy {
                    return Err(bad("the tenancy certificate is for another tenancy"));
                }
                if key_id(cert.agreement_key.as_bytes()) != file.sealed.recipient {
                    return Err(bad("the tenancy certificate names another agreement key"));
                }
            }
            None if !content.rosters.is_empty() => return Err(bad("rosters without a tenancy certificate")),
            None => {}
        }
        content.time_token.verify(store).map_err(|e| BundleRejection::Certificate(format!("time token: {e}")))?;
        if content.time_token.authority_time != content.issued {
            return Err(bad("the issue time isn't the time token's"));
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn check_artefacts(
        &self,
        content: &BundleContent,
        state: &ImportState,
    ) -> Result<(Vec<TrustBundle>, Vec<PolicyDocument>, Vec<ContentAddress>), BundleRejection> {
        let verifier = VerifyPublication::new(TrustStore::new(self.trust), self.publishing).with_provenance_check(ProvenanceCheck::DescribesOnly);
        let groups: [(&[Publication], ArtefactKind); 5] = [
            (&content.instruments, ArtefactKind::Instrument),
            (&content.layouts, ArtefactKind::Layout),
            (&content.localisations, ArtefactKind::Localisation),
            (&content.policy, ArtefactKind::Policy),
            (&content.trust_updates, ArtefactKind::TrustBundle),
        ];
        let mut seen = BTreeSet::new();
        for (publications, kind) in groups {
            for p in publications {
                let address = *p.address();
                if p.artefact.kind() != kind {
                    return Err(BundleRejection::Composition(CompositionError::WrongKind { address, expected: kind, found: p.artefact.kind() }));
                }
                if !seen.insert(address) {
                    return Err(BundleRejection::Artefact { address, error: PublishingError::InvalidArtefact("an artefact appears twice") });
                }
                if kind == ArtefactKind::Instrument {
                    // INS-103: recompute the fingerprint from the salt and the bytes.
                    let recomputed = artefact_address(kind, p.artefact.canonical_bytes(), p.artefact.salt());
                    if recomputed.as_ref() != Ok(&address) {
                        return Err(BundleRejection::Fingerprint(address));
                    }
                }
                verifier.verify(p, &content.withdrawals).map_err(|error| match error {
                    PublishingError::Withdrawn => BundleRejection::Withdrawn(address),
                    error => BundleRejection::Artefact { address, error },
                })?;
            }
        }
        // Withdrawals of artefacts held from earlier bundles.
        let in_bundle: BTreeSet<ContentAddress> = seen;
        let mut withdrawn = Vec::new();
        for w in &content.withdrawals {
            if in_bundle.contains(w.address()) {
                continue;
            }
            if let Some(held) = state.held.publications.iter().find(|p| p.address() == w.address())
                && verifier.verify_withdrawal(w, held).is_ok()
            {
                withdrawn.push(*w.address());
            }
        }

        // Trust updates are valid successors, in order (TRU-033).
        let mut trust_updates = Vec::new();
        let mut current = self.trust.clone();
        for p in &content.trust_updates {
            let bad = |m: &'static str| BundleRejection::Artefact { address: *p.address(), error: PublishingError::InvalidArtefact(m) };
            let candidate = TrustBundle::decode(p.artefact.canonical_bytes()).map_err(|_| bad("a trust update can't be read"))?;
            current.check_update(&candidate).map_err(|_| bad("a trust update isn't a valid successor"))?;
            current = candidate.clone();
            trust_updates.push(candidate);
        }

        // The runtime policy passes the floors (POL-051).
        let mut documents = Vec::new();
        for p in &content.policy {
            let bad = |m: &str| BundleRejection::Policy(format!("{:?}: {m}", p.address()));
            let value = cbor::decode(p.artefact.canonical_bytes()).map_err(|_| bad("not canonical CBOR"))?;
            let document = decode_document(&value).document.ok_or_else(|| bad("not a policy document"))?;
            documents.push(document);
        }
        let layers: Vec<&PolicyDocument> = documents.iter().collect();
        let runtime = RuntimeEvaluator::from_bundle(&layers)
            .map_err(|f| BundleRejection::Policy(format!("{} findings breach the invariant floors", f.len())))?;

        // PUB-072: no tree head may be older than the runtime policy allows, measured from the
        // time token that accompanied it to this bundle's time token.
        let max_age_ms = runtime.policy().max_tree_head_age.as_secs().saturating_mul(AuthorityTime::SECOND);
        let store = TrustStore::new(self.trust);
        for (publications, _) in groups {
            for p in publications {
                check_publication_tree_head_age(p, content.time_token.authority_time, &store, max_age_ms)
                    .map_err(|error| BundleRejection::Artefact { address: *p.address(), error })?;
            }
        }
        Ok((trust_updates, documents, withdrawn))
    }
}

fn check_rosters(content: &BundleContent, referenced: &BTreeSet<String>, held: &HeldState) -> Result<(), BundleRejection> {
    for roster in &content.rosters {
        if let Some(field) = roster.field_names().into_iter().find(|f| !referenced.contains(*f)) {
            return Err(BundleRejection::UnreferencedRosterField { cohort: roster.cohort.clone(), field: field.to_owned() });
        }
        // A roster is certified only when the certificate names its cohort and generation.
        let certified = content
            .certificate
            .as_ref()
            .and_then(|c| c.cohorts.iter().find(|a| a.cohort == roster.cohort))
            .map(|a| a.generation.0);
        if certified != Some(roster.generation.0) {
            return Err(BundleRejection::StaleGeneration {
                cohort: roster.cohort.clone(),
                offered: roster.generation.0,
                certified: certified.unwrap_or(u32::MAX),
            });
        }
        if let Some(h) = held.rosters.iter().find(|h| h.cohort == roster.cohort) {
            let held_roster = Roster { cohort: h.cohort.clone(), version: h.version, generation: h.generation, entries: vec![] };
            held_roster
                .may_be_followed_by(roster)
                .map_err(|error| BundleRejection::Roster { cohort: roster.cohort.clone(), error })?;
        }
    }
    Ok(())
}

/// `ImportBundle` (distribution §3): the hook the Collection core imports bundles through.
///
/// A runtime passes the bytes from any route (DIS-060) with what it holds. On success the
/// bundle is stored sealed, exactly as received, replacing the one held (DIS-033, DIS-050),
/// and the runtime chains the time token and an import record into its journal from the
/// returned [`VerifiedBundle`] (DIS-032). On failure nothing is stored and the held bundle
/// stays (DIS-031); [`BundleRejection::collector_reason`] gives the one-line reason.
pub trait ImportBundle {
    /// Verifies, stores and returns the bundle.
    fn import(&self, bytes: &[u8], state: &ImportState) -> Result<VerifiedBundle, BundleRejection>;
}

/// [`ImportBundle`] over a [`VerifyBundle`] and a [`BundleStore`].
pub struct BundleImporter<'a> {
    verifier: VerifyBundle<'a>,
    store: &'a dyn BundleStore,
}

impl<'a> BundleImporter<'a> {
    /// An importer that verifies with `verifier` and stores into `store`.
    pub fn new(verifier: VerifyBundle<'a>, store: &'a dyn BundleStore) -> Self {
        Self { verifier, store }
    }
}

impl ImportBundle for BundleImporter<'_> {
    fn import(&self, bytes: &[u8], state: &ImportState) -> Result<VerifiedBundle, BundleRejection> {
        let verified = self.verifier.verify(bytes, state)?;
        let sealed = SealedBundle { address: verified.address, tenancy: state.tenancy, seq: verified.content.seq, issued: verified.content.issued, bytes: bytes.to_vec() };
        self.store.put(&sealed).map_err(|e| match e {
            BundleStoreError::NotNewer { held, offered } => BundleRejection::NotNewer { held: held.0, offered: offered.0 },
            BundleStoreError::Backend(_) => BundleRejection::Malformed(fieldseal_kernel::WireError::new(
                ErrorCode::FrameLength,
                0,
                "the bundle couldn't be stored",
            )),
        })?;
        Ok(verified)
    }
}
