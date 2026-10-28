//! Chain building and verification against a trust bundle (TRU-011, TRU-012, TRU-014,
//! TRU-015, TRU-034, TRU-042).

use fieldseal_kernel::crypto::{DomainTag, Purpose, Signature, TagUsage};
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::sign;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value, WireError};

use super::bundle::TrustBundle;
use super::certificate::KeyCertificate;
use super::error::TrustError;
use super::purpose::{KeyRole, signer_role};
use super::revocation::Revocation;

/// What a component trusts: one trust bundle, plus any revocations it has received since
/// (for example in anchors, TRU-041). Every check takes its time from the caller: the
/// signing time stated in the signed structure, or the verifier's authority time for a
/// live check (TRU-012). Nothing here reads a clock.
#[derive(Clone, Debug)]
pub struct TrustStore<'a> {
    bundle: &'a TrustBundle,
    extra_revocations: Vec<Revocation>,
}

impl<'a> TrustStore<'a> {
    /// Trusts exactly the roots of `bundle` (TRU-034).
    pub fn new(bundle: &'a TrustBundle) -> Self {
        Self { bundle, extra_revocations: Vec::new() }
    }

    /// Adds revocations received outside the bundle. Each must be signed by one of the
    /// bundle's roots; any other is refused (`E_SIG`).
    pub fn with_revocations(mut self, revocations: impl IntoIterator<Item = Revocation>) -> Result<Self, TrustError> {
        for r in revocations {
            let root = self.bundle.root(r.issuer()).ok_or(TrustError::UnknownRoot(*r.issuer()))?;
            r.verify_issued_by(root.public_key().as_p256().expect("roots are P-256"))?;
            self.extra_revocations.push(r);
        }
        Ok(self)
    }

    /// The trust bundle.
    pub fn bundle(&self) -> &'a TrustBundle {
        self.bundle
    }

    fn revocations(&self) -> impl Iterator<Item = &Revocation> {
        self.bundle.revocations().iter().chain(&self.extra_revocations)
    }

    /// Verifies one certificate for `required` at `at`, in this order: issuer is a root of the
    /// bundle (else `UnknownRoot`, or `ChainTooLong` if the issuer is itself a certified
    /// purpose key, TRU-014); the root's signature; the role; the root's and the
    /// certificate's validity at `at` (TRU-012); revocation (TRU-042).
    fn check_certificate(&self, cert: &KeyCertificate, required: KeyRole, at: AuthorityTime) -> Result<(), TrustError> {
        let Some(root) = self.bundle.root(cert.issuer()) else {
            if self.bundle.certificates_for(cert.issuer()).next().is_some() || cert.is_root() {
                return Err(TrustError::ChainTooLong);
            }
            return Err(TrustError::UnknownRoot(*cert.issuer()));
        };
        if cert.is_root() {
            // A root's own certificate stands for the root; it is trusted only as listed.
            if root != cert {
                return Err(TrustError::UnknownRoot(*cert.issuer()));
            }
        } else {
            cert.verify_issued_by(root.public_key().as_p256().expect("roots are P-256"))?;
        }
        if cert.role() != required {
            return Err(TrustError::WrongPurpose { certified: cert.role(), required });
        }
        root.check_valid_at(at)?;
        cert.check_valid_at(at)?;
        if let Some(r) = self.revocations().filter(|r| r.invalidates(cert, at)).min_by_key(|r| r.effective()) {
            return Err(TrustError::Revoked { effective: r.effective() });
        }
        Ok(())
    }

    /// Builds and verifies the chain root → `signer` for `purpose` at `at` (TRU §3
    /// `VerifyChain`), returning the signer's certificate.
    ///
    /// `chain` is the certificates presented with the signature (a bundle file's `chain`, a
    /// receiver's `cert`). Chains have depth 1 (TRU-014): `chain` holds at most the signer's
    /// own certificate, issued by a root of the bundle; anything longer is refused. With an
    /// empty `chain`, the certificates pinned in the bundle for `signer` are used, and the
    /// signer is trusted if any of them verifies (so a key re-certified on rotation stays
    /// trusted for signatures made within either validity, TRU-015).
    pub fn verify_chain<'s>(
        &'s self,
        signer: &KeyId,
        chain: &'s [KeyCertificate],
        purpose: Purpose,
        at: AuthorityTime,
    ) -> Result<&'s KeyCertificate, TrustError> {
        self.verify_role(signer, chain, KeyRole::Purpose(purpose), at)
    }

    fn verify_role<'s>(
        &'s self,
        signer: &KeyId,
        chain: &'s [KeyCertificate],
        role: KeyRole,
        at: AuthorityTime,
    ) -> Result<&'s KeyCertificate, TrustError> {
        if role == KeyRole::Root {
            let root = self.bundle.root(signer).ok_or(TrustError::UnknownRoot(*signer))?;
            if chain.iter().any(|c| c != root) {
                return Err(TrustError::ChainTooLong);
            }
            root.check_valid_at(at)?;
            return Ok(root);
        }
        match chain {
            [] => {
                let mut first_error = None;
                for cert in self.bundle.certificates_for(signer) {
                    match self.check_certificate(cert, role, at) {
                        Ok(()) => return Ok(cert),
                        Err(e) => {
                            first_error.get_or_insert(e);
                        }
                    }
                }
                Err(first_error.unwrap_or(TrustError::MissingCertificate(*signer)))
            }
            [cert] => {
                if cert.key_id() != signer {
                    return Err(TrustError::SignerMismatch);
                }
                self.check_certificate(cert, role, at)?;
                Ok(cert)
            }
            _ => Err(TrustError::ChainTooLong),
        }
    }

    /// Verifies a certificate on its own, for its own role, at `at` (`fieldseal trust verify`).
    pub fn verify_certificate(&self, cert: &KeyCertificate, at: AuthorityTime) -> Result<(), TrustError> {
        self.verify_role(cert.key_id(), std::slice::from_ref(cert), cert.role(), at).map(|_| ())
    }

    /// Verifies an authority signature over `structure` under `tag`, by `signer`, made at
    /// `signing_time`. Checks, in order: `tag` is a known signature tag (`E_TAG`, WIRE-020) and
    /// one an authority key signs (`E_TAG`); the chain for the tag's purpose (TRU-011, every
    /// failure `E_SIG`); then the signature itself (`E_SIG`). Root-signed tags (key
    /// certificates, trust bundles, revocations) must be signed by a root of the bundle.
    pub fn verify_signature<'s>(
        &'s self,
        signer: &KeyId,
        chain: &'s [KeyCertificate],
        tag: &DomainTag,
        structure: &Value,
        signature: &Signature,
        signing_time: AuthorityTime,
    ) -> Result<&'s KeyCertificate, TrustError> {
        tag.expect(TagUsage::Signature).map_err(TrustError::BadSignature)?;
        let role = signer_role(tag).ok_or(TrustError::UntrustedTag(tag.as_str()))?;
        let cert = self.verify_role(signer, chain, role, signing_time)?;
        let key = cert
            .public_key()
            .as_p256()
            .ok_or(TrustError::BadSignature(WireError::new(ErrorCode::Sig, 0, "an X25519 key does not sign")))?;
        sign::verify(key, tag, structure, signature).map_err(TrustError::BadSignature)?;
        Ok(cert)
    }
}
