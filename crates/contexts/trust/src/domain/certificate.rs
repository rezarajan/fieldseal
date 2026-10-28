//! Certificate requests and key certificates (TRU §6.4, TRU-010..014, TRU-090..091).

use std::collections::BTreeMap;

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{P256PublicKey, Purpose, Signature, tags};
use fieldseal_kernel::digest;
use fieldseal_kernel::id::{CollectionPeriodId, ContentAddress, KeyId};
use fieldseal_kernel::sign;
use fieldseal_kernel::structure::{Fields, expect_bytes};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value, WireError};

use super::error::TrustError;
use super::period::RecordKeyTerms;
use super::purpose::{KeyAlgorithm, KeyRole, ValidityLimit, validity_limit};
use super::wire::{self, V1, not_defined};

/// An authority public key: P-256 for the root and signing purposes, X25519 for record
/// (and registration sealing) keys (WIRE-009).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum AuthorityPublicKey {
    /// A P-256 key in uncompressed SEC1 form.
    P256(P256PublicKey),
    /// An X25519 key, 32 raw bytes.
    X25519([u8; 32]),
}

impl AuthorityPublicKey {
    /// Reads a key from its WIRE-009 encoding: 65 bytes starting `0x04` for P-256, 32 for
    /// X25519. Any other length is `E_UNKNOWN_FIELD` (the `p256-pub / x25519-pub` choice).
    pub fn from_encoded(bytes: &[u8]) -> Result<Self, WireError> {
        match bytes.len() {
            65 => P256PublicKey::from_bytes(bytes)
                .map(AuthorityPublicKey::P256)
                .map_err(|_| not_defined("P-256 key is not uncompressed SEC1")),
            32 => {
                let key: [u8; 32] = bytes.try_into().expect("32 bytes");
                fieldseal_kernel::crypto::check_x25519_public(&key).map_err(|_| not_defined("X25519 key is a small-order point"))?;
                Ok(AuthorityPublicKey::X25519(key))
            }
            _ => Err(not_defined("public key is neither p256-pub nor x25519-pub")),
        }
    }

    /// The WIRE-009 encoding.
    pub fn encoded(&self) -> &[u8] {
        match self {
            AuthorityPublicKey::P256(k) => k.as_bytes(),
            AuthorityPublicKey::X25519(k) => k,
        }
    }

    /// The key's identifier (WIRE-010).
    pub fn key_id(&self) -> KeyId {
        digest::key_id(self.encoded())
    }

    /// The key's algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            AuthorityPublicKey::P256(_) => KeyAlgorithm::P256,
            AuthorityPublicKey::X25519(_) => KeyAlgorithm::X25519,
        }
    }

    /// The P-256 key, if this is one (only P-256 keys sign).
    pub fn as_p256(&self) -> Option<&P256PublicKey> {
        match self {
            AuthorityPublicKey::P256(k) => Some(k),
            AuthorityPublicKey::X25519(_) => None,
        }
    }
}

/// A certificate signing request: a public key, optionally the purpose it asks for, and
/// for a P-256 key that key's proof of possession.
///
/// TRU-091: a request carrying anything else (a subject name, email address, alternative
/// name, organisation or any other attribute) is refused at construction, so such a request
/// can't exist in the domain. The collection period of a `record` key is a term the issuer
/// sets ([`IssueTerms::record`]), not something the requester asserts.
///
/// TRU-016: a request for a P-256 key carries the key's signature over the request without
/// `sig`, under `fieldseal.dev/csr/v1`; [`Self::verify_possession`] checks it and issuing
/// refuses a request that fails. An X25519 request carries none: the key can't sign, and
/// possession is proved at first use.
///
/// Wire form (`key-request`, TRU §6.4): `{"v": 1, "public_key": p256-pub, ? "purpose": tstr,
/// "sig": signature}` or `{"v": 1, "public_key": x25519-pub, ? "purpose": tstr}`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateRequest {
    public_key: AuthorityPublicKey,
    purpose: Option<Purpose>,
    sig: Option<Signature>,
}

impl CertificateRequest {
    /// Builds an unsigned request. `attributes` are whatever else a submitted CSR carried
    /// (subject fields, alternative names, extensions), as parsed by the adapter that read
    /// it; any attribute at all is refused (TRU-091). A P-256 request then needs
    /// [`Self::with_signature`] before it can be issued (TRU-016).
    pub fn new(
        public_key: AuthorityPublicKey,
        purpose: Option<Purpose>,
        attributes: &BTreeMap<String, String>,
    ) -> Result<Self, TrustError> {
        if !attributes.is_empty() {
            return Err(TrustError::IdentityAttributes(attributes.keys().cloned().collect()));
        }
        Ok(Self { public_key, purpose, sig: None })
    }

    /// The public key to certify.
    pub fn public_key(&self) -> &AuthorityPublicKey {
        &self.public_key
    }

    /// The purpose the requester asked for, if it named one.
    pub fn purpose(&self) -> Option<Purpose> {
        self.purpose
    }

    /// The proof of possession, if the request carries one.
    pub fn signature(&self) -> Option<&Signature> {
        self.sig.as_ref()
    }

    /// The structure the requested key signs: the request without `sig` (TRU-016).
    pub fn signed_structure(&self) -> Value {
        let mut m = BTreeMap::from([
            ("v".to_owned(), V1),
            ("public_key".to_owned(), wire::bytes(self.public_key.encoded())),
        ]);
        if let Some(p) = self.purpose {
            m.insert("purpose".to_owned(), wire::text(p.as_str()));
        }
        Value::Map(m)
    }

    /// Attaches the requested key's signature over [`Self::signed_structure`] under
    /// `fieldseal.dev/csr/v1`. Only P-256 requests are signed.
    pub fn with_signature(mut self, sig: Signature) -> Result<Self, TrustError> {
        if self.public_key.as_p256().is_none() {
            return Err(TrustError::PossessionNotProved);
        }
        self.sig = Some(sig);
        Ok(self)
    }

    /// Signs the request with the software key it is for (tests, practice ceremonies and
    /// software custody; keys in custody sign through [`crate::ports::KeyCustody`]).
    pub fn signed_by(self, key: &sign::SigningKey) -> Result<Self, TrustError> {
        let sig = key.sign(&tags::CSR, &self.signed_structure())?;
        self.with_signature(sig)
    }

    /// Checks the proof of possession (TRU-016): a P-256 request must carry a valid signature
    /// by its own key under `fieldseal.dev/csr/v1` (else `E_SIG`); an X25519 request carries
    /// none, and possession is proved at first use.
    pub fn verify_possession(&self) -> Result<(), TrustError> {
        match (&self.public_key, &self.sig) {
            (AuthorityPublicKey::X25519(_), None) => Ok(()),
            (AuthorityPublicKey::X25519(_), Some(_)) => Err(TrustError::PossessionNotProved),
            (AuthorityPublicKey::P256(_), None) => Err(TrustError::PossessionNotProved),
            (AuthorityPublicKey::P256(k), Some(sig)) => {
                sign::verify(k, &tags::CSR, &self.signed_structure(), sig).map_err(|_| TrustError::PossessionNotProved)
            }
        }
    }

    /// The request as a value.
    pub fn to_value(&self) -> Value {
        let mut v = self.signed_structure();
        if let (Value::Map(m), Some(sig)) = (&mut v, &self.sig) {
            m.insert("sig".to_owned(), wire::bytes(&sig.0));
        }
        v
    }

    /// The canonical CBOR of the request.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value())
    }

    /// Reads a request. Any key besides `v`, `public_key`, `purpose` and `sig` is an identity
    /// attribute and refused as such (TRU-091), not merely as an unknown field. A `sig` on an
    /// X25519 request is `E_UNKNOWN_FIELD`. The signature itself is checked by
    /// [`Self::verify_possession`], which issuing runs.
    pub fn from_value(value: Value) -> Result<Self, TrustError> {
        let mut m = wire::map_value(value)?;
        let extra: Vec<String> =
            m.keys().filter(|k| !matches!(k.as_str(), "v" | "public_key" | "purpose" | "sig")).cloned().collect();
        if !extra.is_empty() {
            return Err(TrustError::IdentityAttributes(extra));
        }
        if m.remove("v") != Some(V1) {
            return Err(WireError::new(ErrorCode::Version, 0, "unknown key-request version").into());
        }
        let public_key = m
            .remove("public_key")
            .ok_or_else(|| not_defined("required field missing"))
            .and_then(expect_bytes)
            .and_then(|b| AuthorityPublicKey::from_encoded(&b))?;
        let purpose = match m.remove("purpose") {
            None => None,
            Some(v) => Some(Purpose::parse(&wire::text_value(v)?).ok_or_else(|| not_defined("unknown purpose"))?),
        };
        let sig = match m.remove("sig") {
            None => None,
            Some(_) if public_key.as_p256().is_none() => return Err(not_defined("X25519 requests are unsigned").into()),
            Some(v) => Some(Signature(fieldseal_kernel::structure::expect_bytes_n::<64>(v)?.to_vec())),
        };
        Ok(Self { public_key, purpose, sig })
    }

    /// Decodes a request from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}

/// What the root decides when it certifies a purpose key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssueTerms {
    /// The one purpose to certify (TRU-010).
    pub purpose: Purpose,
    /// For a `record` key, its collection period and the retention after it (TRU-020);
    /// `None` for any other purpose.
    pub record: Option<RecordKeyTerms>,
    /// Start of validity.
    pub not_before: AuthorityTime,
    /// End of validity (inclusive).
    pub not_after: AuthorityTime,
    /// The serial, unique per root. Issuing is idempotent by key ID and serial.
    pub serial: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Body {
    key_id: KeyId,
    public_key: AuthorityPublicKey,
    role: KeyRole,
    period: Option<CollectionPeriodId>,
    not_before: AuthorityTime,
    not_after: AuthorityTime,
    issuer: KeyId,
    serial: u64,
}

impl Body {
    fn to_value(&self) -> Value {
        let mut m = BTreeMap::from([
            ("v".to_owned(), V1),
            ("key_id".to_owned(), wire::bytes(self.key_id.as_bytes())),
            ("public_key".to_owned(), wire::bytes(self.public_key.encoded())),
            ("purpose".to_owned(), wire::text(self.role.as_str())),
            ("not_before".to_owned(), wire::time(self.not_before)),
            ("not_after".to_owned(), wire::time(self.not_after)),
            ("issuer".to_owned(), wire::bytes(self.issuer.as_bytes())),
            ("serial".to_owned(), wire::uint(self.serial)),
        ]);
        if let Some(p) = &self.period {
            m.insert("period".to_owned(), wire::text(p.as_str()));
        }
        Value::Map(m)
    }

    /// The invariants every certificate holds, whether decoded or issued.
    fn check(&self) -> Result<(), WireError> {
        if self.key_id != self.public_key.key_id() {
            return Err(WireError::new(ErrorCode::Hash, 0, "key_id is not the public key's identifier"));
        }
        if !self.role.allows(self.public_key.algorithm()) {
            return Err(not_defined("key type not allowed for the purpose"));
        }
        if self.period.is_some() != (self.role == KeyRole::Purpose(Purpose::Record)) {
            return Err(not_defined("period is required for, and only allowed on, record keys"));
        }
        if self.role == KeyRole::Root && self.issuer != self.key_id {
            return Err(not_defined("a root certificate is issued by the root itself"));
        }
        if self.not_after <= self.not_before {
            return Err(not_defined("validity is empty: not_after must be after not_before"));
        }
        if let ValidityLimit::AtMost(max_ms) = validity_limit(self.role)
            && self.not_after.0 - self.not_before.0 > max_ms
        {
            return Err(not_defined("validity exceeds the limit for the purpose (TRU-012)"));
        }
        Ok(())
    }
}

/// A key certificate that has not been signed yet: what the issuer is about to sign.
///
/// Constructing one checks every issuing rule, so a certificate the root would refuse can't
/// be put in front of key custody.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedCertificate(Body);

impl UnsignedCertificate {
    /// A root's self-issued certificate (its "root certificate"): P-256, purpose `root`,
    /// issuer and subject the same key, validity at most 10 years (TRU-001, TRU-004).
    pub fn root(public_key: P256PublicKey, not_before: AuthorityTime, not_after: AuthorityTime, serial: u64) -> Result<Self, TrustError> {
        let public_key = AuthorityPublicKey::P256(public_key);
        let key_id = public_key.key_id();
        check_validity(KeyRole::Root, not_before, not_after, None)?;
        Ok(Self(Body { key_id, public_key, role: KeyRole::Root, period: None, not_before, not_after, issuer: key_id, serial }))
    }

    /// A purpose-key certificate issued by `root` for `request` under `terms`.
    ///
    /// Refuses: an issuer that is not a root (chains have depth 1, TRU-014); a P-256 request
    /// without a valid proof of possession (TRU-016); a request that
    /// asked for another purpose; a key type the purpose can't have; a period on a non-record
    /// key or none on a record key (TRU-020); validity that is empty, longer than TRU §6.1
    /// allows (TRU-012), or outside the root's own validity.
    pub fn issue(root: &KeyCertificate, request: &CertificateRequest, terms: IssueTerms) -> Result<Self, TrustError> {
        if root.role() != KeyRole::Root {
            return Err(TrustError::NotAnIssuer);
        }
        request.verify_possession()?;
        let role = KeyRole::Purpose(terms.purpose);
        if let Some(requested) = request.purpose()
            && requested != terms.purpose
        {
            return Err(TrustError::PurposeMismatch { requested: KeyRole::Purpose(requested), issued: role });
        }
        if !role.allows(request.public_key().algorithm()) {
            return Err(TrustError::KeyTypeMismatch(role));
        }
        if terms.record.is_some() != (terms.purpose == Purpose::Record) {
            return Err(TrustError::PeriodMismatch);
        }
        check_validity(role, terms.not_before, terms.not_after, terms.record.as_ref())?;
        if terms.not_before < root.not_before() || terms.not_after > root.not_after() {
            return Err(TrustError::OutsideIssuerValidity);
        }
        let public_key = request.public_key().clone();
        let body = Body {
            key_id: public_key.key_id(),
            public_key,
            role,
            period: terms.record.map(|r| r.period.id().clone()),
            not_before: terms.not_before,
            not_after: terms.not_after,
            issuer: *root.key_id(),
            serial: terms.serial,
        };
        body.check()?;
        Ok(Self(body))
    }

    /// The structure the issuer signs: the certificate without `sig` (WIRE-021).
    pub fn signed_structure(&self) -> Value {
        self.0.to_value()
    }

    /// The issuer's key ID.
    pub fn issuer(&self) -> &KeyId {
        &self.0.issuer
    }

    /// The subject's key ID.
    pub fn key_id(&self) -> &KeyId {
        &self.0.key_id
    }

    /// Attaches the issuer's signature, checking it under `fieldseal.dev/key-certificate/v1`
    /// against `issuer_key` (the root's public key; for a root certificate, its own).
    pub fn finish(self, sig: Signature, issuer_key: &P256PublicKey) -> Result<KeyCertificate, TrustError> {
        if digest::key_id(issuer_key.as_bytes()) != self.0.issuer {
            return Err(TrustError::SignerMismatch);
        }
        let cert = KeyCertificate { body: self.0, sig };
        cert.verify_issued_by(issuer_key)?;
        Ok(cert)
    }
}

fn check_validity(
    role: KeyRole,
    not_before: AuthorityTime,
    not_after: AuthorityTime,
    record: Option<&RecordKeyTerms>,
) -> Result<(), TrustError> {
    if not_after <= not_before {
        return Err(TrustError::EmptyValidity);
    }
    match (validity_limit(role), record) {
        (ValidityLimit::AtMost(max_ms), _) if not_after.0 - not_before.0 > max_ms => {
            Err(TrustError::ValidityTooLong { role, max_ms })
        }
        (ValidityLimit::PeriodPlusRetention, Some(r)) => {
            let latest = r.latest_not_after()?;
            if not_after > latest {
                return Err(TrustError::ValidityTooLong { role, max_ms: latest.0.saturating_sub(not_before.0) });
            }
            Ok(())
        }
        (ValidityLimit::PeriodPlusRetention, None) => Err(TrustError::PeriodMismatch),
        _ => Ok(()),
    }
}

/// A root's signed statement binding a public key to one role and a validity period
/// (TRU §6.4), signed over `fieldseal.dev/key-certificate/v1`.
///
/// TRU-090: the subject is identified only by its [`KeyId`]; the type has no field for
/// names, email addresses, organisations or other identity attributes, and the decoder
/// rejects any such field (`E_UNKNOWN_FIELD`, WIRE-005).
///
/// A *root certificate* is the root's self-issued certificate with purpose `root`; a
/// trust bundle lists roots by their root certificates.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyCertificate {
    body: Body,
    sig: Signature,
}

impl KeyCertificate {
    /// The subject key's identifier (WIRE-010).
    pub fn key_id(&self) -> &KeyId {
        &self.body.key_id
    }

    /// The certified public key.
    pub fn public_key(&self) -> &AuthorityPublicKey {
        &self.body.public_key
    }

    /// The role: `root` for a root certificate, else the single purpose (TRU-010).
    pub fn role(&self) -> KeyRole {
        self.body.role
    }

    /// The purpose, for a purpose-key certificate.
    pub fn purpose(&self) -> Option<Purpose> {
        self.body.role.purpose()
    }

    /// The collection period, for `record` keys.
    pub fn period(&self) -> Option<&CollectionPeriodId> {
        self.body.period.as_ref()
    }

    /// Start of validity.
    pub fn not_before(&self) -> AuthorityTime {
        self.body.not_before
    }

    /// End of validity (inclusive).
    pub fn not_after(&self) -> AuthorityTime {
        self.body.not_after
    }

    /// The issuing root's key identifier.
    pub fn issuer(&self) -> &KeyId {
        &self.body.issuer
    }

    /// The certificate's serial, unique per issuer.
    pub fn serial(&self) -> u64 {
        self.body.serial
    }

    /// The issuer's signature.
    pub fn signature(&self) -> &Signature {
        &self.sig
    }

    /// Whether this is a root's self-issued certificate.
    pub fn is_root(&self) -> bool {
        self.body.role == KeyRole::Root
    }

    /// Whether `at` falls within the validity period (TRU-012).
    pub fn valid_at(&self, at: AuthorityTime) -> bool {
        self.body.not_before <= at && at <= self.body.not_after
    }

    /// `Ok` if `at` falls within the validity period, else why not (TRU-012).
    pub fn check_valid_at(&self, at: AuthorityTime) -> Result<(), TrustError> {
        if at < self.body.not_before {
            Err(TrustError::NotYetValid)
        } else if at > self.body.not_after {
            Err(TrustError::Expired)
        } else {
            Ok(())
        }
    }

    /// The structure the issuer signed: the certificate without `sig`.
    pub fn signed_structure(&self) -> Value {
        self.body.to_value()
    }

    /// Checks the issuer's signature under `fieldseal.dev/key-certificate/v1`.
    pub fn verify_issued_by(&self, issuer_key: &P256PublicKey) -> Result<(), TrustError> {
        sign::verify(issuer_key, &tags::KEY_CERTIFICATE, &self.signed_structure(), &self.sig).map_err(TrustError::BadSignature)
    }

    /// The certificate as a value.
    pub fn to_value(&self) -> Value {
        let mut v = self.body.to_value();
        if let Value::Map(m) = &mut v {
            m.insert("sig".to_owned(), wire::bytes(&self.sig.0));
        }
        v
    }

    /// The canonical CBOR of the certificate.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value())
    }

    /// The certificate's content address (WIRE-011).
    pub fn content_address(&self) -> Result<ContentAddress, WireError> {
        Ok(ContentAddress::of(&self.encode()?))
    }

    /// Reads a certificate. Refuses: an unknown version (`E_VERSION`); any field not in
    /// TRU §6.4, a missing or mistyped field, an unknown purpose, a key type the purpose
    /// can't have, a period on a non-record key or none on a record key, or a root
    /// certificate issued by another key (`E_UNKNOWN_FIELD`); a `key_id` that is not the
    /// public key's identifier (`E_HASH`). The signature is checked by chain verification.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("v", &V1)?;
        let key_id = wire::key_id(&mut f, "key_id")?;
        let public_key = AuthorityPublicKey::from_encoded(&f.bytes("public_key")?)?;
        let role = KeyRole::parse(&f.text("purpose")?).ok_or_else(|| not_defined("unknown purpose"))?;
        let period = match f.take_opt("period") {
            None => None,
            Some(v) => Some(CollectionPeriodId::new(wire::text_value(v)?).map_err(|_| not_defined("empty period"))?),
        };
        let body = Body {
            key_id,
            public_key,
            role,
            period,
            not_before: wire::auth_time(&mut f, "not_before")?,
            not_after: wire::auth_time(&mut f, "not_after")?,
            issuer: wire::key_id(&mut f, "issuer")?,
            serial: f.uint("serial")?,
        };
        let sig = wire::signature(&mut f, "sig")?;
        f.finish()?;
        body.check()?;
        Ok(Self { body, sig })
    }

    /// Decodes a certificate from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}
