//! Root revocations (TRU-040..042).

use std::collections::BTreeMap;

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{P256PublicKey, Signature, tags};
use fieldseal_kernel::digest;
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::sign;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, WireError};

use super::certificate::KeyCertificate;
use super::error::TrustError;
use super::wire::{self, V1, not_defined};

/// Why a key or certificate was revoked.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RevocationReason {
    /// The private key is known or suspected to be compromised.
    Compromised,
    /// The key was replaced in a routine rotation.
    Superseded,
    /// The key holder left their role.
    HolderLeft,
    /// The key's service was retired (for example, an intake host decommissioned).
    Retired,
}

impl RevocationReason {
    /// The reason as written on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            RevocationReason::Compromised => "compromised",
            RevocationReason::Superseded => "superseded",
            RevocationReason::HolderLeft => "holder-left",
            RevocationReason::Retired => "retired",
        }
    }

    /// Parses a reason; `None` for any other text.
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Compromised, Self::Superseded, Self::HolderLeft, Self::Retired].into_iter().find(|r| r.as_str() == text)
    }
}

/// What a revocation names (TRU-040): a key (every certificate for it), or one certificate
/// by its issuer and serial.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RevocationTarget {
    /// The revoked key.
    pub key_id: KeyId,
    /// If set, only the certificate with this serial from the revoking root is revoked.
    pub serial: Option<u64>,
}

impl RevocationTarget {
    /// Every certificate for `key_id`.
    pub fn key(key_id: KeyId) -> Self {
        Self { key_id, serial: None }
    }

    /// The one certificate `cert`.
    pub fn certificate(cert: &KeyCertificate) -> Self {
        Self { key_id: *cert.key_id(), serial: Some(cert.serial()) }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Body {
    target: RevocationTarget,
    reason: RevocationReason,
    effective: AuthorityTime,
    issued: AuthorityTime,
    issuer: KeyId,
}

impl Body {
    fn to_value(&self) -> Value {
        let mut m = BTreeMap::from([
            ("v".to_owned(), V1),
            ("key_id".to_owned(), wire::bytes(self.target.key_id.as_bytes())),
            ("reason".to_owned(), wire::text(self.reason.as_str())),
            ("effective".to_owned(), wire::time(self.effective)),
            ("issued".to_owned(), wire::time(self.issued)),
            ("issuer".to_owned(), wire::bytes(self.issuer.as_bytes())),
        ]);
        if let Some(s) = self.target.serial {
            m.insert("serial".to_owned(), wire::uint(s));
        }
        Value::Map(m)
    }
}

/// A revocation the root has not signed yet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedRevocation(Body);

impl UnsignedRevocation {
    /// A revocation of `target` by `root` (a root certificate), for `reason`, effective from
    /// `effective`, issued at `issued`.
    pub fn new(
        root: &KeyCertificate,
        target: RevocationTarget,
        reason: RevocationReason,
        effective: AuthorityTime,
        issued: AuthorityTime,
    ) -> Result<Self, TrustError> {
        if !root.is_root() {
            return Err(TrustError::NotAnIssuer);
        }
        Ok(Self(Body { target, reason, effective, issued, issuer: *root.key_id() }))
    }

    /// The structure the root signs (WIRE-021).
    pub fn signed_structure(&self) -> Value {
        self.0.to_value()
    }

    /// The revoking root's key ID.
    pub fn issuer(&self) -> &KeyId {
        &self.0.issuer
    }

    /// Attaches the root's signature, checking it against `root_key`.
    pub fn finish(self, sig: Signature, root_key: &P256PublicKey) -> Result<Revocation, TrustError> {
        if digest::key_id(root_key.as_bytes()) != self.0.issuer {
            return Err(TrustError::SignerMismatch);
        }
        let r = Revocation { body: self.0, sig };
        r.verify_issued_by(root_key)?;
        Ok(r)
    }
}

/// A root-signed statement that a key or certificate is no longer valid from an effective
/// time (TRU-040), signed over `fieldseal.dev/revocation/v1`.
///
/// Wire form (`revocation`, TRU §6.4): `{"v": 1, "key_id": key-id, ? "serial": uint,
/// "reason": tstr, "effective": ms-time, "issued": ms-time, "issuer": key-id, "sig": signature}`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Revocation {
    body: Body,
    sig: Signature,
}

impl Revocation {
    /// What is revoked.
    pub fn target(&self) -> RevocationTarget {
        self.body.target
    }

    /// Why.
    pub fn reason(&self) -> RevocationReason {
        self.body.reason
    }

    /// From when signatures by the key are invalid (TRU-042).
    pub fn effective(&self) -> AuthorityTime {
        self.body.effective
    }

    /// When the root signed it.
    pub fn issued(&self) -> AuthorityTime {
        self.body.issued
    }

    /// The revoking root's key ID.
    pub fn issuer(&self) -> &KeyId {
        &self.body.issuer
    }

    /// The root's signature.
    pub fn signature(&self) -> &Signature {
        &self.sig
    }

    /// Whether this revocation names `cert`: its key, or exactly this certificate.
    pub fn applies_to(&self, cert: &KeyCertificate) -> bool {
        let t = &self.body.target;
        t.key_id == *cert.key_id() && t.serial.is_none_or(|s| s == cert.serial() && self.body.issuer == *cert.issuer())
    }

    /// Whether a signature by `cert` made at `signing_time` is invalid because of this
    /// revocation: it names the certificate and took effect at or before then (TRU-042).
    pub fn invalidates(&self, cert: &KeyCertificate, signing_time: AuthorityTime) -> bool {
        self.applies_to(cert) && self.body.effective <= signing_time
    }

    /// The structure the root signed.
    pub fn signed_structure(&self) -> Value {
        self.body.to_value()
    }

    /// Checks the root's signature under `fieldseal.dev/revocation/v1`.
    pub fn verify_issued_by(&self, root_key: &P256PublicKey) -> Result<(), TrustError> {
        sign::verify(root_key, &tags::REVOCATION, &self.signed_structure(), &self.sig).map_err(TrustError::BadSignature)
    }

    /// The revocation as a value.
    pub fn to_value(&self) -> Value {
        let mut v = self.body.to_value();
        if let Value::Map(m) = &mut v {
            m.insert("sig".to_owned(), wire::bytes(&self.sig.0));
        }
        v
    }

    /// The canonical CBOR of the revocation.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value())
    }

    /// Reads a revocation; any field not defined is `E_UNKNOWN_FIELD`, an unknown version
    /// `E_VERSION`. The signature is checked against the trust bundle's roots.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("v", &V1)?;
        let key_id = wire::key_id(&mut f, "key_id")?;
        let serial = f.take_opt("serial").map(fieldseal_kernel::structure::expect_uint).transpose()?;
        let reason = RevocationReason::parse(&f.text("reason")?).ok_or_else(|| not_defined("unknown revocation reason"))?;
        let body = Body {
            target: RevocationTarget { key_id, serial },
            reason,
            effective: wire::auth_time(&mut f, "effective")?,
            issued: wire::auth_time(&mut f, "issued")?,
            issuer: wire::key_id(&mut f, "issuer")?,
        };
        let sig = wire::signature(&mut f, "sig")?;
        f.finish()?;
        Ok(Self { body, sig })
    }

    /// Decodes a revocation from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}
