//! Trust bundles (TRU-030..035, TRU-093, TRU §6.5).

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{Purpose, Signature, tags};
use fieldseal_kernel::id::{ContentAddress, Digest, KeyId};
use fieldseal_kernel::sign;
use fieldseal_kernel::structure::{Fields, expect_bytes, expect_bytes_n};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, WireError};

use super::certificate::KeyCertificate;
use super::error::TrustError;
use super::purpose::ROOT_MAX_VALIDITY_MS;
use super::revocation::Revocation;
use super::wire::{self, V1, not_defined};

/// A trust bundle's version, `MAJOR.MINOR.PATCH`, compared numerically (TRU-033).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct BundleVersion {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
}

impl BundleVersion {
    /// Parses `MAJOR.MINOR.PATCH` (decimal, no leading zeros, no pre-release or build part).
    pub fn parse(text: &str) -> Result<Self, TrustError> {
        let part = |s: &str| {
            let ok = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
            ok.then(|| s.parse::<u64>().ok()).flatten().ok_or(TrustError::InvalidVersion)
        };
        let mut it = text.split('.');
        let (Some(a), Some(b), Some(c), None) = (it.next(), it.next(), it.next(), it.next()) else {
            return Err(TrustError::InvalidVersion);
        };
        Ok(Self { major: part(a)?, minor: part(b)?, patch: part(c)? })
    }
}

impl core::fmt::Display for BundleVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A runtime build the authority accepts (TRU-030): platform, application identity and the
/// digests of the signing certificates it may be signed with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuntimeBuild {
    /// Platform name, for example `android`.
    pub platform: String,
    /// Application identity (package name or team and bundle ID).
    pub app_id: String,
    /// SHA-256 digests of the accepted signing certificates.
    pub signing_digests: Vec<Digest>,
}

/// A pinned transparency log (TRU-093): its origin, its checkpoint key and the checkpoint
/// format that key signs (for example `c2sp-tlog-checkpoint`, WIRE-192).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LogPin {
    /// The log's origin line, as it appears in its checkpoints.
    pub origin: String,
    /// The log's public key, in the encoding of the checkpoint format.
    pub public_key: Vec<u8>,
    /// The checkpoint format.
    pub format: String,
}

/// Everything a trust bundle lists (TRU-030, TRU-093).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TrustBundleContents {
    /// The authority's name for the bundle (its artefact name).
    pub name: String,
    /// The bundle's version; an update must be higher (TRU-033).
    pub version: BundleVersion,
    /// When the root signed it.
    pub issued: AuthorityTime,
    /// The roots, as their self-issued root certificates (TRU-034).
    pub roots: Vec<KeyCertificate>,
    /// Purpose-key certificates (pins), each issued by a listed root.
    pub certificates: Vec<KeyCertificate>,
    /// Publisher keys accepted per artefact kind (PUB-040), by key ID; each must have a
    /// `publisher` certificate in [`Self::certificates`].
    pub publishers: BTreeMap<String, Vec<KeyId>>,
    /// Attestation roots per evidence format (TRU-062), as the format's encoding (DER for
    /// X.509 chains).
    pub attestation_roots: BTreeMap<String, Vec<Vec<u8>>>,
    /// Accepted runtime builds.
    pub runtime_builds: Vec<RuntimeBuild>,
    /// Pinned transparency logs (TRU-093).
    pub logs: Vec<LogPin>,
    /// Root revocations (TRU-041).
    pub revocations: Vec<Revocation>,
}

fn entry(detail: &'static str) -> TrustError {
    TrustError::InvalidBundleEntry(detail)
}

impl TrustBundleContents {
    fn root(&self, id: &KeyId) -> Option<&KeyCertificate> {
        self.roots.iter().find(|r| r.key_id() == id)
    }

    /// Every rule a bundle's contents must meet, independently of its signatures.
    fn check(&self) -> Result<(), TrustError> {
        if self.name.is_empty() {
            return Err(entry("name is empty"));
        }
        if self.roots.is_empty() {
            return Err(TrustError::InvalidRoots("a trust bundle lists at least one root"));
        }
        let mut seen = BTreeSet::new();
        for root in &self.roots {
            let key = root.public_key().as_p256().ok_or(TrustError::InvalidRoots("roots are P-256"))?;
            if !root.is_root() {
                return Err(TrustError::InvalidRoots("a root entry must be a root certificate"));
            }
            if root.not_after().0.saturating_sub(root.not_before().0) > ROOT_MAX_VALIDITY_MS {
                return Err(TrustError::InvalidRoots("a root's validity must not exceed 10 years"));
            }
            root.verify_issued_by(key)?;
            if !seen.insert(*root.key_id()) {
                return Err(TrustError::InvalidRoots("a root is listed twice"));
            }
        }
        let mut serials = BTreeSet::new();
        for cert in &self.certificates {
            if cert.is_root() {
                return Err(entry("root certificates belong in roots"));
            }
            let root = self.root(cert.issuer()).ok_or(TrustError::UntrustedEntry("certificate not issued by a listed root"))?;
            cert.verify_issued_by(root.public_key().as_p256().expect("checked"))?;
            if !serials.insert((*cert.issuer(), cert.serial())) {
                return Err(entry("two certificates with one issuer and serial"));
            }
        }
        for (kind, keys) in &self.publishers {
            if kind.is_empty() || keys.is_empty() {
                return Err(entry("publisher kinds name at least one key"));
            }
            if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
                return Err(entry("a publisher key is listed twice for one artefact kind"));
            }
            for k in keys {
                if !self.certificates.iter().any(|c| c.key_id() == k && c.purpose() == Some(Purpose::Publisher)) {
                    return Err(entry("publisher key has no publisher certificate in the bundle"));
                }
            }
        }
        if self.attestation_roots.iter().any(|(f, roots)| f.is_empty() || roots.is_empty() || roots.iter().any(Vec::is_empty)) {
            return Err(entry("attestation roots are listed per named format"));
        }
        if self.attestation_roots.values().any(|roots| roots.iter().collect::<BTreeSet<_>>().len() != roots.len()) {
            return Err(entry("an attestation root is listed twice for one format"));
        }
        if self.runtime_builds.iter().any(|b| b.platform.is_empty() || b.app_id.is_empty() || b.signing_digests.is_empty()) {
            return Err(entry("runtime builds need a platform, app ID and signing digest"));
        }
        let mut builds = BTreeSet::new();
        for b in &self.runtime_builds {
            if !builds.insert((&b.platform, &b.app_id)) {
                return Err(entry("a runtime build is listed twice (platform and app ID)"));
            }
            if b.signing_digests.iter().collect::<BTreeSet<_>>().len() != b.signing_digests.len() {
                return Err(entry("a signing digest is listed twice for one runtime build"));
            }
        }
        let mut origins = BTreeSet::new();
        for log in &self.logs {
            if log.origin.is_empty() || log.public_key.is_empty() || log.format.is_empty() || !origins.insert(&log.origin) {
                return Err(entry("logs are pinned once each, by origin, key and format"));
            }
            // WIRE-195: a `c2sp-tlog-checkpoint` key is a P-256 key in uncompressed SEC1 form.
            if log.format == "c2sp-tlog-checkpoint" && fieldseal_kernel::crypto::P256PublicKey::from_bytes(&log.public_key).is_err() {
                return Err(entry("a c2sp-tlog-checkpoint log key is a valid uncompressed P-256 point"));
            }
        }
        let mut revoked = BTreeSet::new();
        for r in &self.revocations {
            if !revoked.insert((*r.issuer(), r.target().key_id, r.target().serial, r.effective())) {
                return Err(entry("a revocation is listed twice"));
            }
            let root = self.root(r.issuer()).ok_or(TrustError::UntrustedEntry("revocation not issued by a listed root"))?;
            r.verify_issued_by(root.public_key().as_p256().expect("checked"))?;
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let certs = |v: &[KeyCertificate]| Value::Array(v.iter().map(KeyCertificate::to_value).collect());
        cbor::map([
            ("v", V1),
            ("name", wire::text(&self.name)),
            ("version", wire::text(&self.version.to_string())),
            ("issued", wire::time(self.issued)),
            ("roots", certs(&self.roots)),
            ("certificates", certs(&self.certificates)),
            (
                "publishers",
                Value::Map(
                    self.publishers
                        .iter()
                        .map(|(k, ids)| (k.clone(), Value::Array(ids.iter().map(|i| wire::bytes(i.as_bytes())).collect())))
                        .collect(),
                ),
            ),
            (
                "attestation_roots",
                Value::Map(
                    self.attestation_roots
                        .iter()
                        .map(|(f, roots)| (f.clone(), Value::Array(roots.iter().map(|r| wire::bytes(r)).collect())))
                        .collect(),
                ),
            ),
            (
                "runtime_builds",
                Value::Array(
                    self.runtime_builds
                        .iter()
                        .map(|b| {
                            cbor::map([
                                ("platform", wire::text(&b.platform)),
                                ("app_id", wire::text(&b.app_id)),
                                (
                                    "signing_digests",
                                    Value::Array(b.signing_digests.iter().map(|d| wire::bytes(d.as_bytes())).collect()),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "logs",
                Value::Array(
                    self.logs
                        .iter()
                        .map(|l| {
                            cbor::map([
                                ("origin", wire::text(&l.origin)),
                                ("public_key", wire::bytes(&l.public_key)),
                                ("format", wire::text(&l.format)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("revocations", Value::Array(self.revocations.iter().map(Revocation::to_value).collect())),
        ])
    }

    fn from_fields(f: &mut Fields) -> Result<Self, TrustError> {
        f.version("v", &V1)?;
        let array = |v: Value| match v {
            Value::Array(a) => Ok(a),
            _ => Err(not_defined("field is not an array")),
        };
        let certs = |f: &mut Fields, key: &str| -> Result<Vec<KeyCertificate>, WireError> {
            f.array(key)?.into_iter().map(KeyCertificate::from_value).collect()
        };
        let name = f.text("name")?;
        let version = BundleVersion::parse(&f.text("version")?)?;
        let issued = wire::auth_time(f, "issued")?;
        let roots = certs(f, "roots")?;
        let certificates = certs(f, "certificates")?;
        let publishers = wire::map_value(f.take("publishers")?)?
            .into_iter()
            .map(|(k, v)| {
                let ids = array(v)?.into_iter().map(|i| expect_bytes_n::<16>(i).map(KeyId::from)).collect::<Result<_, _>>()?;
                Ok((k, ids))
            })
            .collect::<Result<_, WireError>>()?;
        let attestation_roots = wire::map_value(f.take("attestation_roots")?)?
            .into_iter()
            .map(|(k, v)| Ok((k, array(v)?.into_iter().map(expect_bytes).collect::<Result<_, _>>()?)))
            .collect::<Result<_, WireError>>()?;
        let runtime_builds = f
            .array("runtime_builds")?
            .into_iter()
            .map(|b| {
                let mut g = Fields::new(b)?;
                let build = RuntimeBuild {
                    platform: g.text("platform")?,
                    app_id: g.text("app_id")?,
                    signing_digests: g
                        .array("signing_digests")?
                        .into_iter()
                        .map(|d| expect_bytes_n::<32>(d).map(Digest::from))
                        .collect::<Result<_, _>>()?,
                };
                g.finish()?;
                Ok(build)
            })
            .collect::<Result<_, WireError>>()?;
        let logs = f
            .array("logs")?
            .into_iter()
            .map(|l| {
                let mut g = Fields::new(l)?;
                let log = LogPin { origin: g.text("origin")?, public_key: g.bytes("public_key")?, format: g.text("format")? };
                g.finish()?;
                Ok(log)
            })
            .collect::<Result<_, WireError>>()?;
        let revocations = f.array("revocations")?.into_iter().map(Revocation::from_value).collect::<Result<_, _>>()?;
        Ok(Self {
            name,
            version,
            issued,
            roots,
            certificates,
            publishers,
            attestation_roots,
            runtime_builds,
            logs,
            revocations,
        })
    }
}

/// One root's signature over a trust bundle.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BundleSignature {
    /// The signing root's key ID.
    pub signer: KeyId,
    /// The signature over `fieldseal.dev/trust-bundle/v1`.
    pub sig: Signature,
}

/// A trust bundle whose contents are valid but which no root has signed yet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedTrustBundle(TrustBundleContents);

impl UnsignedTrustBundle {
    /// Checks `contents` (every root self-issued and at most 10 years, every certificate and
    /// revocation issued by a listed root with a valid signature, publisher keys certified,
    /// logs pinned once) and puts the lists in canonical order, so that the same contents
    /// always build the same bytes.
    pub fn new(mut contents: TrustBundleContents) -> Result<Self, TrustError> {
        for keys in contents.publishers.values_mut() {
            keys.sort();
            keys.dedup();
        }
        contents.check()?;
        contents.roots.sort_by_key(|r| *r.key_id());
        contents.certificates.sort_by_key(|c| (*c.issuer(), c.serial(), *c.key_id()));
        contents.revocations.sort_by_key(|r| (*r.issuer(), r.target().key_id, r.target().serial, r.effective()));
        contents.runtime_builds.sort_by(|a, b| (&a.platform, &a.app_id).cmp(&(&b.platform, &b.app_id)));
        contents.logs.sort_by(|a, b| a.origin.cmp(&b.origin));
        Ok(Self(contents))
    }

    /// What will be listed.
    pub fn contents(&self) -> &TrustBundleContents {
        &self.0
    }

    /// The structure each root signs: the bundle without `signatures` (WIRE-021).
    pub fn signed_structure(&self) -> Value {
        self.0.to_value()
    }

    /// Attaches the roots' signatures and checks them (see [`TrustBundle::from_value`]).
    pub fn finish(self, signatures: Vec<BundleSignature>) -> Result<TrustBundle, TrustError> {
        let bundle = TrustBundle { contents: self.0, signatures };
        bundle.verify_signatures()?;
        Ok(bundle)
    }
}

/// The roots, purpose-key certificates, attestation roots, accepted runtime builds, pinned
/// logs and revocations a component accepts (TRU-030, TRU-093), signed by one or more of
/// the roots it lists over `fieldseal.dev/trust-bundle/v1` (TRU-031).
///
/// A `TrustBundle` value is always internally valid: every signature, root certificate,
/// purpose-key certificate and revocation in it has been checked.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrustBundle {
    contents: TrustBundleContents,
    signatures: Vec<BundleSignature>,
}

impl TrustBundle {
    fn verify_signatures(&self) -> Result<(), TrustError> {
        if self.signatures.is_empty() {
            return Err(TrustError::BundleSigner);
        }
        let structure = self.contents.to_value();
        let mut signers = BTreeSet::new();
        for s in &self.signatures {
            let root = self.contents.root(&s.signer).ok_or(TrustError::BundleSigner)?;
            if !signers.insert(s.signer) {
                return Err(TrustError::BundleSigner);
            }
            root.check_valid_at(self.contents.issued)?;
            let key = root.public_key().as_p256().expect("roots are P-256");
            sign::verify(key, &tags::TRUST_BUNDLE, &structure, &s.sig).map_err(TrustError::BadSignature)?;
        }
        Ok(())
    }

    /// Everything the bundle lists.
    pub fn contents(&self) -> &TrustBundleContents {
        &self.contents
    }

    /// The bundle's name.
    pub fn name(&self) -> &str {
        &self.contents.name
    }

    /// The bundle's version.
    pub fn version(&self) -> BundleVersion {
        self.contents.version
    }

    /// When the bundle was signed.
    pub fn issued(&self) -> AuthorityTime {
        self.contents.issued
    }

    /// The roots' signatures.
    pub fn signatures(&self) -> &[BundleSignature] {
        &self.signatures
    }

    /// The root certificate for `key_id`, if it is one of this bundle's roots (TRU-034).
    pub fn root(&self, key_id: &KeyId) -> Option<&KeyCertificate> {
        self.contents.root(key_id)
    }

    /// The roots.
    pub fn roots(&self) -> &[KeyCertificate] {
        &self.contents.roots
    }

    /// Pinned purpose-key certificates for `key_id`.
    pub fn certificates_for<'s>(&'s self, key_id: &KeyId) -> impl Iterator<Item = &'s KeyCertificate> + use<'s> {
        let id = *key_id;
        self.contents.certificates.iter().filter(move |c| *c.key_id() == id)
    }

    /// Every pinned purpose-key certificate.
    pub fn certificates(&self) -> &[KeyCertificate] {
        &self.contents.certificates
    }

    /// The revocations the bundle carries.
    pub fn revocations(&self) -> &[Revocation] {
        &self.contents.revocations
    }

    /// The publisher certificates accepted for artefact `kind` (PUB-040).
    pub fn publishers_for(&self, kind: &str) -> Vec<&KeyCertificate> {
        let keys = self.contents.publishers.get(kind).map(Vec::as_slice).unwrap_or_default();
        self.contents
            .certificates
            .iter()
            .filter(|c| c.purpose() == Some(Purpose::Publisher) && keys.contains(c.key_id()))
            .collect()
    }

    /// The attestation roots for evidence `format` (TRU-062); empty if none are listed.
    pub fn attestation_roots(&self, format: &str) -> &[Vec<u8>] {
        self.contents.attestation_roots.get(format).map(Vec::as_slice).unwrap_or_default()
    }

    /// Whether the bundle accepts a runtime build (TRU-030).
    pub fn accepts_build(&self, platform: &str, app_id: &str, signing_digest: &Digest) -> bool {
        self.contents
            .runtime_builds
            .iter()
            .any(|b| b.platform == platform && b.app_id == app_id && b.signing_digests.contains(signing_digest))
    }

    /// The pinned log for `origin`, if `public_key` is its pinned key (TRU-093). A checkpoint
    /// signed by any other key, or from an unpinned origin, is refused (`E_SIG`).
    pub fn pinned_log(&self, origin: &str, public_key: &[u8]) -> Result<&LogPin, TrustError> {
        self.contents
            .logs
            .iter()
            .find(|l| l.origin == origin && l.public_key == public_key)
            .ok_or_else(|| TrustError::LogNotPinned(origin.to_owned()))
    }

    /// Checks that `candidate` may replace this bundle (TRU-033, TRU-004): it is for the same
    /// authority (name), its version is higher, at least one of this bundle's roots signed it,
    /// and every root it adds also signed it.
    pub fn check_update(&self, candidate: &TrustBundle) -> Result<(), TrustError> {
        if candidate.name() != self.name() || candidate.version() <= self.version() {
            return Err(TrustError::UpdateNotNewer);
        }
        let signed_by = |id: &KeyId| candidate.signatures.iter().any(|s| s.signer == *id);
        if !self.roots().iter().any(|r| signed_by(r.key_id()) && candidate.root(r.key_id()) == Some(r)) {
            return Err(TrustError::UpdateSigner);
        }
        for root in candidate.roots() {
            if self.root(root.key_id()).is_none() && !signed_by(root.key_id()) {
                return Err(TrustError::NewRootUnsigned(*root.key_id()));
            }
        }
        Ok(())
    }

    /// The bundle as a value.
    pub fn to_value(&self) -> Value {
        let mut v = self.contents.to_value();
        if let Value::Map(m) = &mut v {
            m.insert(
                "signatures".to_owned(),
                Value::Array(
                    self.signatures
                        .iter()
                        .map(|s| cbor::map([("signer", wire::bytes(s.signer.as_bytes())), ("sig", wire::bytes(&s.sig.0))]))
                        .collect(),
                ),
            );
        }
        v
    }

    /// The canonical CBOR of the bundle.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value())
    }

    /// The bundle's content address (WIRE-011).
    pub fn content_address(&self) -> Result<ContentAddress, WireError> {
        Ok(ContentAddress::of(&self.encode()?))
    }

    /// Reads and checks a bundle. Refuses a malformed structure with its WIRE code
    /// (`E_UNKNOWN_FIELD` for any field not in TRU §6.5); then contents that break a rule of
    /// [`UnsignedTrustBundle::new`]; then a bundle with no signature, a signature by a key that
    /// is not one of its roots or by a root not valid at `issued` (TRU-031), or a signature
    /// that does not verify (`E_SIG`).
    pub fn from_value(value: Value) -> Result<Self, TrustError> {
        let mut f = Fields::new(value)?;
        let contents = TrustBundleContents::from_fields(&mut f)?;
        let signatures = f
            .array("signatures")?
            .into_iter()
            .map(|s| {
                let mut g = Fields::new(s)?;
                let sig = BundleSignature { signer: wire::key_id(&mut g, "signer")?, sig: wire::signature(&mut g, "sig")? };
                g.finish()?;
                Ok(sig)
            })
            .collect::<Result<_, WireError>>()?;
        f.finish()?;
        contents.check()?;
        let bundle = Self { contents, signatures };
        bundle.verify_signatures()?;
        Ok(bundle)
    }

    /// Decodes and checks a bundle from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}
