//! Use cases offered by the Trust context (TRU §3).
//!
//! The authority-side use cases ([`Authority`]) are what `fieldseal trust root-init`,
//! `issue`, `bundle` and `revoke` run: each builds the structure in the domain (where every
//! issuing rule is checked), has the right key in [`KeyCustody`] sign it, and checks the
//! signature before returning. [`verify_chain`] backs `fieldseal trust verify` and every
//! context's signature checks; it needs no port. Nothing here reads a clock: authority time
//! is an input.

use fieldseal_kernel::crypto::{P256PublicKey, Purpose, Signature, tags};
use fieldseal_kernel::id::{KeyId, Nonce};
use fieldseal_kernel::time::AuthorityTime;

use crate::domain::{
    AttestationClaims, AttestationEvidence, BundleSignature, Ceremony, CeremonyRecord, CertificateRequest, IssueTerms,
    KeyAlgorithm, KeyCertificate, KeyRole, RecordKeyTerms, Revocation, RevocationReason, RevocationTarget, TrustBundle,
    TrustBundleContents, TrustError, TrustStore, UnsignedCertificate, UnsignedRevocation, UnsignedTrustBundle,
};
use crate::ports::{AttestationVerifier, CustodyError, KeyCustody, VerificationError};

/// Why an authority use case failed: the domain refused, or key custody did.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UseCaseError {
    /// A Trust rule refused the request.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// Key custody refused or failed.
    #[error(transparent)]
    Custody(#[from] CustodyError),
}

/// The result of rotating a purpose key (TRU §3 `RotatePurposeKey`, TRU-015).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rotation {
    /// The new key's certificate.
    pub certificate: KeyCertificate,
    /// The end of the old key's validity, unchanged: signatures it made within its validity
    /// stay valid (TRU-015). It is not revoked.
    pub previous_not_after: AuthorityTime,
    /// How long both keys are valid at once, in milliseconds (0 if the validities don't meet).
    pub overlap_ms: u64,
}

/// The authority-side use cases, run as `caller` against `custody` (the offline signer for
/// root operations). Every custody use is logged under `caller`.
pub struct Authority<'a, C: KeyCustody + ?Sized> {
    custody: &'a C,
    caller: &'a str,
}

impl<'a, C: KeyCustody + ?Sized> Authority<'a, C> {
    /// Uses `custody`, logging every key use as `caller`.
    pub fn new(custody: &'a C, caller: &'a str) -> Self {
        Self { custody, caller }
    }

    fn root_key(root: &KeyCertificate) -> Result<&P256PublicKey, TrustError> {
        if !root.is_root() {
            return Err(TrustError::NotAnIssuer);
        }
        root.public_key().as_p256().ok_or(TrustError::NotAnIssuer)
    }

    fn sign_as_root(&self, root: &KeyId, tag: &fieldseal_kernel::crypto::DomainTag, s: &fieldseal_kernel::Value) -> Result<Signature, CustodyError> {
        self.custody.sign(root, KeyRole::Root, tag, s, self.caller)
    }

    /// `InitRoot` (`fieldseal trust root-init`): checks the ceremony (TRU-002), generates the
    /// P-256 root inside custody (TRU-001), has it issue its own root certificate (validity at
    /// most 10 years, TRU-004) and returns the ceremony record with it.
    pub fn init_root(&self, ceremony: Ceremony) -> Result<CeremonyRecord, UseCaseError> {
        ceremony.check()?;
        let key = self.custody.generate(KeyRole::Root, KeyAlgorithm::P256)?;
        let public = key.public_key.as_p256().ok_or(CustodyError::Unsupported)?.clone();
        let unsigned = UnsignedCertificate::root(public.clone(), ceremony.not_before, ceremony.not_after, 0)?;
        let sig = self.sign_as_root(&key.id, &tags::KEY_CERTIFICATE, &unsigned.signed_structure())?;
        let root = unsigned.finish(sig, &public)?;
        Ok(CeremonyRecord::new(ceremony, root)?)
    }

    /// The certificate request an operator exports for `key`, a key in custody (step 4 of
    /// the operator guide): its public key, optionally the purpose it asks for, and for a
    /// P-256 key its proof of possession, signed in custody (TRU-016). X25519 requests are
    /// unsigned. Never any identity attribute (TRU-091).
    pub fn request(&self, key: &KeyId, purpose: Option<Purpose>) -> Result<CertificateRequest, UseCaseError> {
        let held = self.custody.public_key(key)?;
        let request = CertificateRequest::new(held.public_key.clone(), purpose, &std::collections::BTreeMap::new())?;
        if held.public_key.as_p256().is_none() {
            return Ok(request);
        }
        let sig = self.custody.sign(key, held.role, &tags::CSR, &request.signed_structure(), self.caller)?;
        Ok(request.with_signature(sig)?)
    }

    /// `IssuePurposeKey` (`fieldseal trust issue`): certifies `request`'s key for one purpose
    /// under `terms`, signed by `root` in custody. The request must carry no identity
    /// attribute (TRU-091) and, for a P-256 key, must prove possession (TRU-016); see
    /// [`UnsignedCertificate::issue`] for every other check. Only a
    /// root issues, so chains have depth 1 (TRU-014).
    pub fn issue(&self, root: &KeyCertificate, request: &CertificateRequest, terms: IssueTerms) -> Result<KeyCertificate, UseCaseError> {
        let root_key = Self::root_key(root)?;
        let unsigned = UnsignedCertificate::issue(root, request, terms)?;
        let sig = self.sign_as_root(root.key_id(), &tags::KEY_CERTIFICATE, &unsigned.signed_structure())?;
        Ok(unsigned.finish(sig, root_key)?)
    }

    /// `OpenCollectionPeriod`: certifies an X25519 `record` key for `terms.period`, valid
    /// from `not_before` to the period's end plus retention (TRU-020, TRU §6.1).
    pub fn open_collection_period(
        &self,
        root: &KeyCertificate,
        request: &CertificateRequest,
        terms: RecordKeyTerms,
        not_before: AuthorityTime,
        serial: u64,
    ) -> Result<KeyCertificate, UseCaseError> {
        let not_after = terms.latest_not_after()?;
        self.issue(root, request, IssueTerms { purpose: Purpose::Record, record: Some(terms), not_before, not_after, serial })
    }

    /// `RotatePurposeKey`: certifies a successor to `current` for the same purpose. The old
    /// certificate is left as it is, so signatures it made within its validity keep verifying
    /// (TRU-015); publish a trust bundle carrying both. Record keys are not rotated: each
    /// collection period gets its own ([`Self::open_collection_period`]).
    pub fn rotate(
        &self,
        root: &KeyCertificate,
        current: &KeyCertificate,
        request: &CertificateRequest,
        not_before: AuthorityTime,
        not_after: AuthorityTime,
        serial: u64,
    ) -> Result<Rotation, UseCaseError> {
        let purpose = current.purpose().ok_or(TrustError::NotAnIssuer)?;
        if purpose == Purpose::Record {
            return Err(TrustError::PeriodMismatch.into());
        }
        if request.public_key() == current.public_key() {
            return Err(TrustError::InvalidBundleEntry("a rotation certifies a new key").into());
        }
        let certificate = self.issue(root, request, IssueTerms { purpose, record: None, not_before, not_after, serial })?;
        let overlap_ms = current.not_after().0.saturating_sub(not_before.0.max(current.not_before().0));
        Ok(Rotation { certificate, previous_not_after: current.not_after(), overlap_ms })
    }

    /// `Revoke` (`fieldseal trust revoke`): a root-signed revocation of a key or one
    /// certificate, with a reason and effective time (TRU-040). Publish it in the next trust
    /// bundle (TRU-041).
    pub fn revoke(
        &self,
        root: &KeyCertificate,
        target: RevocationTarget,
        reason: RevocationReason,
        effective: AuthorityTime,
        issued: AuthorityTime,
    ) -> Result<Revocation, UseCaseError> {
        let root_key = Self::root_key(root)?;
        let unsigned = UnsignedRevocation::new(root, target, reason, effective, issued)?;
        let sig = self.sign_as_root(root.key_id(), &tags::REVOCATION, &unsigned.signed_structure())?;
        Ok(unsigned.finish(sig, root_key)?)
    }

    /// `BuildTrustBundle` (`fieldseal trust bundle`): checks `contents`, has each root in
    /// `signers` sign it (each must be listed in it, TRU-031), and, if `previous` is the
    /// bundle components hold now, checks that they will accept this one (TRU-033: a higher
    /// version signed by a current root; TRU-004: a new root signs too). To replace a root,
    /// list both roots and sign with both.
    pub fn build_bundle(
        &self,
        contents: TrustBundleContents,
        signers: &[&KeyCertificate],
        previous: Option<&TrustBundle>,
    ) -> Result<TrustBundle, UseCaseError> {
        let unsigned = UnsignedTrustBundle::new(contents)?;
        let structure = unsigned.signed_structure();
        let mut signatures = Vec::with_capacity(signers.len());
        for root in signers {
            if unsigned.contents().roots.iter().all(|r| r.key_id() != root.key_id()) {
                return Err(TrustError::BundleSigner.into());
            }
            let sig = self.sign_as_root(root.key_id(), &tags::TRUST_BUNDLE, &structure)?;
            signatures.push(BundleSignature { signer: *root.key_id(), sig });
        }
        let bundle = unsigned.finish(signatures)?;
        if let Some(previous) = previous {
            previous.check_update(&bundle)?;
        }
        Ok(bundle)
    }
}

/// `VerifyChain` (`fieldseal trust verify`): verifies `signer`'s chain to a root of `bundle`
/// for `purpose` at `at`, honouring the bundle's revocations and `revocations` received
/// since (TRU-011, TRU-012, TRU-014, TRU-034, TRU-042). Returns the signer's certificate.
pub fn verify_chain(
    bundle: &TrustBundle,
    revocations: Vec<Revocation>,
    signer: &KeyId,
    chain: &[KeyCertificate],
    purpose: Purpose,
    at: AuthorityTime,
) -> Result<KeyCertificate, TrustError> {
    let store = TrustStore::new(bundle).with_revocations(revocations)?;
    store.verify_chain(signer, chain, purpose, at).cloned()
}

/// `VerifyEvidence`: verifies attestation evidence with the verifier for its format,
/// against the trust bundle's attestation roots for that format (TRU-062).
pub struct VerifyEvidence<'a> {
    verifiers: Vec<&'a dyn AttestationVerifier>,
}

/// The evidence format of software key stores: always unattested (TRU-061, TRU §6.2).
pub const SOFTWARE_EVIDENCE_FORMAT: &str = "software";

impl<'a> VerifyEvidence<'a> {
    /// Uses `verifiers`, one per accepted evidence format.
    pub fn new(verifiers: Vec<&'a dyn AttestationVerifier>) -> Self {
        Self { verifiers }
    }

    /// Verifies `evidence` for `key` and `challenge`. Evidence in a format with no
    /// configured verifier is refused, never trusted; so is a hardware format for which the
    /// bundle lists no attestation roots. `software` evidence has no roots and yields only
    /// `software` claims (TRU-061); whether that suffices is policy's decision (TRU-065).
    pub fn verify(
        &self,
        bundle: &TrustBundle,
        evidence: &AttestationEvidence,
        challenge: &Nonce,
        key: &P256PublicKey,
    ) -> Result<AttestationClaims, VerificationError> {
        let verifier = self
            .verifiers
            .iter()
            .find(|v| v.format() == evidence.format)
            .ok_or_else(|| VerificationError::UnsupportedFormat(evidence.format.clone()))?;
        let roots = bundle.attestation_roots(&evidence.format);
        if roots.is_empty() && evidence.format != SOFTWARE_EVIDENCE_FORMAT {
            return Err(VerificationError::NoRoots(evidence.format.clone()));
        }
        let claims = verifier.verify(evidence, challenge, key, roots)?;
        if evidence.format == SOFTWARE_EVIDENCE_FORMAT && claims.is_attested() {
            return Err(VerificationError::Invalid("software evidence must yield software claims".into()));
        }
        Ok(claims)
    }
}
