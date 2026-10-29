//! The byte forms of the Registration context's structures (WIRE §5.9–§5.13, §6.6) and the
//! device-side builders for them.
//!
//! Every structure here is deterministic CBOR through the kernel; every decoder refuses
//! unknown fields (`E_UNKNOWN_FIELD`), unknown versions (`E_VERSION`) and oversized input
//! (`E_SIZE`). Signed structures are signed over `[tag, structure-without-sig]`
//! (WIRE-021); the factory signs through `KeyCustody`, devices through their key store,
//! which is why the builders hand out the message to sign rather than taking a key.

use std::collections::BTreeMap;

use fieldseal_kernel::crypto::{DomainTag, P256PublicKey, Signature, tags};
use fieldseal_kernel::digest::{key_id, sha256};
use fieldseal_kernel::id::{CohortId, ContentAddress, Digest, Generation, KeyId, Nonce, Seq, TenancyHandle, TenancyId};
use fieldseal_kernel::seal::{self, RecipientKey, SealedBox};
use fieldseal_kernel::sign;
use fieldseal_kernel::structure::{Fields, expect_bytes_n, expect_uint};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{CryptoRng, ErrorCode, Value, WireError, cbor, text};
use fieldseal_trust::domain::{AttestationEvidence, DeviceKeyKind, TrustBundle, TrustError, TrustStore};

use super::{
    CloseReason, CohortAssignment, KeyEvidence, ManagementMode, NonceSource, PostureReport,
    RegistrationRequest, RegistrationRoute, RegistrationToken, ReportedProfile,
    ReportedRestriction, ReportedVersion, RollProof, TokenSecret, Window,
};

/// The largest registration request (WIRE §6.7).
pub const MAX_REQUEST: usize = 64 * 1024;
/// The longest factory URL in a token (WIRE-121).
pub const MAX_FACTORY_URL: usize = 256;
/// The magic of a registration request file (WIRE-136).
pub const REQUEST_FILE_MAGIC: &[u8; 4] = b"FSRQ";
/// The largest posture report.
pub const MAX_POSTURE_REPORT: usize = 64 * 1024;

fn unknown(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn uint(n: u64) -> Value {
    Value::Int(i128::from(n))
}

fn text_value(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn version(f: &mut Fields) -> Result<(), WireError> {
    f.version("v", &Value::Int(1))
}

fn p256(f: &mut Fields, key: &str) -> Result<P256PublicKey, WireError> {
    let b = f.bytes_n::<65>(key)?;
    P256PublicKey::from_bytes(&b).map_err(|_| unknown("not an uncompressed P-256 key"))
}

fn signature(f: &mut Fields) -> Result<Signature, WireError> {
    Ok(Signature(f.bytes_n::<64>("sig")?.to_vec()))
}

fn with_sig(mut structure: Value, sig: &Signature) -> Value {
    if let Value::Map(m) = &mut structure {
        m.insert("sig".into(), bytes(&sig.0));
    }
    structure
}

fn encode_limited(value: &Value, limit: usize) -> Result<Vec<u8>, WireError> {
    let out = cbor::encode(value)?;
    if out.len() > limit {
        return Err(WireError::new(ErrorCode::Size, limit, "structure exceeds its size limit"));
    }
    Ok(out)
}

/// Whether `url` is acceptable as a token's factory URL (WIRE-121): `https`, at most 256
/// bytes. Plain `http` is accepted only for a loopback host, so a factory can run locally
/// for development; a device on a real network can't reach it.
pub fn factory_url_ok(url: &str) -> bool {
    if url.len() > MAX_FACTORY_URL {
        return false;
    }
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty();
    }
    url.strip_prefix("http://").is_some_and(|rest| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit_once(':').map_or(host, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { host });
        matches!(host, "localhost" | "127.0.0.1" | "[::1]")
    })
}

/// The SHA-256 of a root public key, as a token names it (WIRE-121).
pub fn root_fingerprint(encoded_public_key: &[u8]) -> Digest {
    sha256(encoded_public_key)
}

// ---------------------------------------------------------------------------------------
// Registration token (WIRE-120..124).

/// Why a device refuses a token (REG-010).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TokenRefusal {
    /// The token's trust root isn't a root of the device's trust bundle.
    #[error("the token's trust root is not in the trust bundle")]
    UnknownRoot,
    /// The token's signature doesn't verify to that root.
    #[error("token signature: {0}")]
    Signature(TrustError),
}

impl RegistrationToken {
    /// The signed structure: the token without `sig`.
    pub fn signed_structure(&self) -> Value {
        cbor::map([
            ("v", uint(1)),
            ("factory", text_value(&self.factory)),
            ("root", bytes(self.trust_root.as_bytes())),
            ("token", bytes(self.secret.as_bytes())),
            ("nonce", bytes(self.nonce.as_bytes())),
            ("mode", text_value(self.route.as_str())),
            ("issued", uint(self.issued_at.0)),
            ("signer", bytes(self.signer.as_bytes())),
        ])
    }

    /// The whole token.
    pub fn to_value(&self) -> Value {
        with_sig(self.signed_structure(), &self.signature)
    }

    /// Canonical CBOR, at most 300 bytes (WIRE-123).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        encode_limited(&self.to_value(), text::MAX_QR_OBJECT)
    }

    /// Decodes canonical CBOR.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode_limited(input, text::MAX_QR_OBJECT)?)?;
        version(&mut f)?;
        let factory = f.text("factory")?;
        if !factory_url_ok(&factory) {
            return Err(unknown("factory is not an https URL of at most 256 bytes"));
        }
        let trust_root = Digest::from(f.bytes_n::<32>("root")?);
        let secret = TokenSecret::from_bytes(f.bytes_n::<16>("token")?);
        let nonce = Nonce::from(f.bytes_n::<32>("nonce")?);
        let route = RegistrationRoute::parse(&f.text("mode")?).ok_or(unknown("mode is not online or air-gapped"))?;
        let issued_at = AuthorityTime(f.uint("issued")?);
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let signature = signature(&mut f)?;
        f.finish()?;
        Ok(Self { factory, trust_root, secret, nonce, route, issued_at, signer, signature })
    }

    /// The text form `FS1T:…` (WIRE-122), also what the QR code encodes.
    pub fn to_text(&self) -> Result<String, WireError> {
        Ok(text::encode(text::TOKEN_PREFIX, &self.encode()?))
    }

    /// Reads the text form.
    pub fn from_text(input: &str) -> Result<Self, WireError> {
        Self::decode(&text::decode(text::TOKEN_PREFIX, input)?)
    }

    /// The device's check on reading a token (REG-010): its trust root must be a root of
    /// `bundle`, and its signature must verify by a `registration` key certified by that
    /// root, at the token's issue time. The device never evaluates expiry (WIRE-124).
    pub fn verify(&self, bundle: &TrustBundle) -> Result<(), TokenRefusal> {
        let root = bundle
            .roots()
            .iter()
            .find(|r| root_fingerprint(r.public_key().encoded()) == self.trust_root)
            .ok_or(TokenRefusal::UnknownRoot)?;
        let store = TrustStore::new(bundle);
        let cert = store
            .verify_signature(&self.signer, &[], &tags::REGISTRATION_TOKEN, &self.signed_structure(), &self.signature, self.issued_at)
            .map_err(TokenRefusal::Signature)?;
        if cert.issuer() != root.key_id() {
            return Err(TokenRefusal::UnknownRoot);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Registration request (WIRE-130..136).

fn evidence_key(kind: DeviceKeyKind) -> &'static str {
    match kind {
        DeviceKeyKind::Signing => "sign",
        DeviceKeyKind::Agreement => "agree",
        DeviceKeyKind::Wrapping => "storage",
    }
}

fn parse_evidence_key(text: &str) -> Option<DeviceKeyKind> {
    match text {
        "sign" => Some(DeviceKeyKind::Signing),
        "agree" => Some(DeviceKeyKind::Agreement),
        "storage" => Some(DeviceKeyKind::Wrapping),
        _ => None,
    }
}

/// The body of a registration request (WIRE-130), as the device builds it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RequestBody {
    /// The token secret.
    pub token: TokenSecret,
    /// The nonce: the token's factory nonce, or the device's own (REG-011).
    pub nonce: Nonce,
    /// Where the nonce came from.
    pub nonce_source: NonceSource,
    /// The signing public key; the tenancy ID is its SHA-256 (WIRE-131).
    pub sign_pub: P256PublicKey,
    /// The agreement public key.
    pub agree_pub: P256PublicKey,
    /// Evidence for each key (at least one entry).
    pub evidence: Vec<KeyEvidence>,
    /// The runtime build identity.
    pub build: String,
    /// The previous tenancy's closing hash on this device.
    pub prev_closing: Option<Digest>,
    /// A nickname for the device.
    pub label: Option<String>,
    /// The schema version and catalogue version the runtime reports (WIRE-130).
    pub profile: ReportedProfile,
}

/// The structure a proof of possession signs: `{nonce, body_sha256}` (WIRE-132).
pub fn pop_structure(nonce: &Nonce, body_digest: &Digest) -> Value {
    cbor::map([("nonce", bytes(nonce.as_bytes())), ("body_sha256", bytes(body_digest.as_bytes()))])
}

/// The exact message a key store signs for a proof of possession (WIRE-021, WIRE-132).
pub fn pop_message(nonce: &Nonce, body_digest: &Digest) -> Vec<u8> {
    sign::signed_message(&tags::REGISTRATION_POP, &pop_structure(nonce, body_digest)).expect("encodable")
}

/// Verifies a proof of possession by `key` over `{nonce, body_sha256}`.
pub fn verify_pop(key: &P256PublicKey, nonce: &Nonce, body_digest: &Digest, sig: &Signature) -> Result<(), WireError> {
    sign::verify(key, &tags::REGISTRATION_POP, &pop_structure(nonce, body_digest), sig)
}

impl RequestBody {
    /// The tenancy ID this body declares: SHA-256 of `sign_pub`.
    pub fn tenancy(&self) -> TenancyId {
        TenancyId::from(*sha256(self.sign_pub.as_bytes()).as_bytes())
    }

    /// The body as a value.
    pub fn to_value(&self) -> Value {
        let mut m: BTreeMap<String, Value> = BTreeMap::new();
        m.insert("v".into(), uint(1));
        m.insert("token".into(), bytes(self.token.as_bytes()));
        m.insert("nonce".into(), bytes(self.nonce.as_bytes()));
        m.insert("nonce_source".into(), text_value(self.nonce_source.as_str()));
        m.insert("tenancy".into(), bytes(self.tenancy().as_bytes()));
        m.insert("sign_pub".into(), bytes(self.sign_pub.as_bytes()));
        m.insert("agree_pub".into(), bytes(self.agree_pub.as_bytes()));
        m.insert(
            "evidence".into(),
            Value::Array(
                self.evidence
                    .iter()
                    .map(|e| {
                        cbor::map([
                            ("key", text_value(evidence_key(e.kind))),
                            ("format", text_value(&e.evidence.format)),
                            ("data", bytes(&e.evidence.data)),
                        ])
                    })
                    .collect(),
            ),
        );
        m.insert("build".into(), text_value(&self.build));
        m.insert(
            "schema".into(),
            text_value(&self.profile.instrument_schema.to_string()),
        );
        if let Some(c) = &self.profile.catalogue_reference {
            m.insert("catalogue".into(), text_value(c));
        }
        if let Some(p) = &self.prev_closing {
            m.insert("prev_closing".into(), bytes(p.as_bytes()));
        }
        if let Some(l) = &self.label {
            m.insert("label".into(), text_value(l));
        }
        Value::Map(m)
    }

    /// Canonical CBOR of the body.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a request body is encodable")
    }

    /// SHA-256 of the canonical body: what the proof of possession and the fingerprint
    /// words are computed from.
    pub fn digest(&self) -> Digest {
        sha256(&self.encode())
    }

    /// The message the signing key must sign as proof of possession.
    pub fn pop_message(&self) -> Vec<u8> {
        pop_message(&self.nonce, &self.digest())
    }

    /// Reads a body, checking `tenancy` = SHA-256(`sign_pub`) (WIRE-131, `E_HASH`).
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        version(&mut f)?;
        let token = TokenSecret::from_bytes(f.bytes_n::<16>("token")?);
        let nonce = Nonce::from(f.bytes_n::<32>("nonce")?);
        let nonce_source = match f.text("nonce_source")?.as_str() {
            "factory" => NonceSource::Factory,
            "device" => NonceSource::Device,
            _ => return Err(unknown("nonce_source is not factory or device")),
        };
        let tenancy = f.bytes_n::<32>("tenancy")?;
        let sign_pub = p256(&mut f, "sign_pub")?;
        let agree_pub = p256(&mut f, "agree_pub")?;
        let mut evidence = Vec::new();
        for e in f.array("evidence")? {
            let mut ef = Fields::new(e)?;
            let kind = parse_evidence_key(&ef.text("key")?).ok_or(unknown("evidence key is not sign, agree or storage"))?;
            let format = ef.text("format")?;
            let data = ef.bytes("data")?;
            ef.finish()?;
            evidence.push(KeyEvidence { kind, evidence: AttestationEvidence { format, data } });
        }
        if evidence.is_empty() {
            return Err(unknown("evidence must not be empty"));
        }
        if evidence.iter().any(|e| e.evidence.format.is_empty()) {
            return Err(unknown("an evidence format is named"));
        }
        let mut kinds = std::collections::BTreeSet::new();
        if !evidence.iter().all(|e| kinds.insert(evidence_key(e.kind))) {
            return Err(unknown("evidence is given once per key"));
        }
        let build = f.text("build")?;
        if build.is_empty() {
            return Err(unknown("build must not be empty"));
        }
        let schema = f.text("schema")?;
        if schema.len() > ReportedVersion::MAX_TEXT {
            return Err(WireError::new(
                ErrorCode::Size,
                ReportedVersion::MAX_TEXT,
                "schema exceeds 32 bytes",
            ));
        }
        let instrument_schema =
            ReportedVersion::parse(&schema).ok_or(unknown("schema is not major.minor.patch"))?;
        let catalogue_reference = match f.take_opt("catalogue") {
            None => None,
            Some(Value::Text(t)) if t.len() > ReportedProfile::MAX_CATALOGUE => {
                return Err(WireError::new(
                    ErrorCode::Size,
                    ReportedProfile::MAX_CATALOGUE,
                    "catalogue exceeds 64 bytes",
                ));
            }
            Some(Value::Text(t)) if ReportedProfile::catalogue_ok(&t) => Some(t),
            Some(_) => {
                return Err(unknown(
                    "catalogue is not a non-empty text without control characters",
                ));
            }
        };
        let prev_closing = f
            .take_opt("prev_closing")
            .map(expect_bytes_n::<32>)
            .transpose()?
            .map(Digest::from);
        let label = match f.take_opt("label") {
            None => None,
            Some(Value::Text(t)) => Some(t),
            Some(_) => return Err(unknown("label is not text")),
        };
        f.finish()?;
        let profile = ReportedProfile {
            instrument_schema,
            catalogue_reference,
        };
        let body = Self {
            token,
            nonce,
            nonce_source,
            sign_pub,
            agree_pub,
            evidence,
            build,
            prev_closing,
            label,
            profile,
        };
        if body.tenancy().as_bytes() != &tenancy {
            return Err(WireError::new(ErrorCode::Hash, 0, "tenancy is not SHA-256 of sign_pub"));
        }
        Ok(body)
    }

    /// Builds the plaintext `{body, pop, roll?}` and seals it to the factory's registration
    /// key (WIRE-134). `pop` is the signing key's signature over [`Self::pop_message`];
    /// `roll` is set on a key roll (REG-060).
    pub fn seal(
        &self,
        rng: &mut impl CryptoRng,
        factory: &RecipientKey,
        pop: &Signature,
        roll: Option<&RollProof>,
    ) -> Result<SealedBox, WireError> {
        let mut entries = vec![("body", self.to_value()), ("pop", bytes(&pop.0))];
        if let Some(r) = roll {
            entries.push(("roll", cbor::map([("tenancy", bytes(r.tenancy.as_bytes())), ("sig", bytes(&r.signature.0))])));
        }
        seal::seal_value(rng, factory, &tags::REGISTRATION_SEAL, &cbor::map(entries))
    }
}

/// Reads an unsealed request plaintext `{body, pop, roll?}` (at most 64 KiB).
pub fn decode_request(plaintext: &[u8]) -> Result<RegistrationRequest, WireError> {
    let mut f = Fields::new(cbor::decode_limited(plaintext, MAX_REQUEST)?)?;
    let body = RequestBody::from_value(f.take("body")?)?;
    let pop = Signature(f.bytes_n::<64>("pop")?.to_vec());
    let roll = match f.take_opt("roll") {
        None => None,
        Some(v) => {
            let mut rf = Fields::new(v)?;
            let tenancy = TenancyId::from(rf.bytes_n::<32>("tenancy")?);
            let signature = signature(&mut rf)?;
            rf.finish()?;
            Some(RollProof { tenancy, signature })
        }
    };
    f.finish()?;
    let body_digest = body.digest();
    Ok(RegistrationRequest {
        token: body.token,
        nonce: body.nonce,
        nonce_source: body.nonce_source,
        tenancy: body.tenancy(),
        sign_pub: body.sign_pub,
        agree_pub: body.agree_pub,
        evidence: body.evidence,
        build: body.build,
        prev_closing: body.prev_closing,
        label: body.label,
        profile: body.profile,
        body_digest,
        proof_of_possession: pop,
        roll,
    })
}

/// A sealed request as a file (WIRE-136): `FSRQ` and the sealed box's canonical CBOR.
pub fn encode_request_file(sealed: &SealedBox) -> Vec<u8> {
    let mut out = REQUEST_FILE_MAGIC.to_vec();
    out.extend_from_slice(&sealed.encode());
    out
}

/// Reads a request file, or a bare sealed box (the online route sends the box alone).
pub fn decode_request_file(input: &[u8]) -> Result<SealedBox, WireError> {
    if input.len() > MAX_REQUEST + REQUEST_FILE_MAGIC.len() {
        return Err(WireError::new(ErrorCode::Size, 0, "request exceeds 64 KiB"));
    }
    let body = input.strip_prefix(REQUEST_FILE_MAGIC.as_slice()).unwrap_or(input);
    SealedBox::from_value(cbor::decode_limited(body, MAX_REQUEST)?)
}

// ---------------------------------------------------------------------------------------
// Tenancy certificate (WIRE-140).

/// A key in a tenancy certificate's key history.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertifiedKey {
    /// The key's index in the tenancy's key history.
    pub index: u32,
    /// The signing public key.
    pub public_key: P256PublicKey,
}

/// The factory's signed statement of a registered tenancy (WIRE-140, REG-032).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenancyCertificate {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The opaque collector reference.
    pub collector: Vec<u8>,
    /// The export handle.
    pub handle: TenancyHandle,
    /// The signing-key history, by index.
    pub keys: Vec<CertifiedKey>,
    /// The agreement public key bundles are sealed to.
    pub agreement_key: P256PublicKey,
    /// The collection period's record-key ID.
    pub record_key: KeyId,
    /// The window.
    pub window: Window,
    /// Cohorts with generations.
    pub cohorts: Vec<CohortAssignment>,
    /// The attested device serial, when policy requires it.
    pub serial: Option<String>,
    /// When it was issued.
    pub issued_at: AuthorityTime,
    /// The factory policy that approved it.
    pub policy: ContentAddress,
    /// The registration key that signed it.
    pub signer: KeyId,
    /// The signature over tag `fieldseal.dev/tenancy-certificate/v1`.
    pub signature: Signature,
}

impl TenancyCertificate {
    /// The signed structure: the certificate without `sig`.
    pub fn signed_structure(&self) -> Value {
        let mut m: BTreeMap<String, Value> = BTreeMap::new();
        m.insert("v".into(), uint(1));
        m.insert("tenancy".into(), bytes(self.tenancy.as_bytes()));
        m.insert("collector".into(), bytes(&self.collector));
        m.insert("handle".into(), bytes(self.handle.as_bytes()));
        m.insert(
            "keys".into(),
            Value::Array(
                self.keys
                    .iter()
                    .map(|k| cbor::map([("index", uint(u64::from(k.index))), ("public_key", bytes(k.public_key.as_bytes()))]))
                    .collect(),
            ),
        );
        m.insert("agree_pub".into(), bytes(self.agreement_key.as_bytes()));
        m.insert("period".into(), bytes(self.record_key.as_bytes()));
        m.insert(
            "window".into(),
            cbor::map([
                ("not_before", uint(self.window.not_before.0)),
                ("not_after", uint(self.window.not_after.0)),
                ("grace", uint(self.window.grace_ms)),
            ]),
        );
        m.insert(
            "cohorts".into(),
            Value::Array(
                self.cohorts
                    .iter()
                    .map(|c| cbor::map([("cohort", text_value(c.cohort.as_str())), ("generation", uint(u64::from(c.generation.0)))]))
                    .collect(),
            ),
        );
        if let Some(s) = &self.serial {
            m.insert("serial".into(), text_value(s));
        }
        m.insert("issued".into(), uint(self.issued_at.0));
        m.insert("policy".into(), bytes(self.policy.as_bytes()));
        m.insert("signer".into(), bytes(self.signer.as_bytes()));
        Value::Map(m)
    }

    /// The whole certificate.
    pub fn to_value(&self) -> Value {
        with_sig(self.signed_structure(), &self.signature)
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a tenancy certificate is encodable")
    }

    /// Reads a certificate from a value.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        version(&mut f)?;
        let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
        let collector = f.bytes("collector")?;
        let handle = TenancyHandle::from(f.bytes_n::<16>("handle")?);
        let mut keys = Vec::new();
        for k in f.array("keys")? {
            let mut kf = Fields::new(k)?;
            let index = u32::try_from(kf.uint("index")?).map_err(|_| unknown("key index out of range"))?;
            let public_key = p256(&mut kf, "public_key")?;
            kf.finish()?;
            keys.push(CertifiedKey { index, public_key });
        }
        if keys.is_empty() {
            return Err(unknown("a tenancy certificate lists at least one key"));
        }
        if keys.iter().map(|k| k.index).collect::<std::collections::BTreeSet<_>>().len() != keys.len() {
            return Err(unknown("key indices are unique"));
        }
        let agreement_key = p256(&mut f, "agree_pub")?;
        let record_key = KeyId::from(f.bytes_n::<16>("period")?);
        let mut wf = Fields::new(f.take("window")?)?;
        let window = Window {
            not_before: AuthorityTime(wf.uint("not_before")?),
            not_after: AuthorityTime(wf.uint("not_after")?),
            grace_ms: wf.uint("grace")?,
        };
        wf.finish()?;
        if window.not_after < window.not_before {
            return Err(unknown("window ends before it starts"));
        }
        let mut cohorts = Vec::new();
        for c in f.array("cohorts")? {
            let mut cf = Fields::new(c)?;
            let cohort = CohortId::new(cf.text("cohort")?).map_err(|_| unknown("empty cohort"))?;
            let generation = Generation(u32::try_from(cf.uint("generation")?).map_err(|_| unknown("generation out of range"))?);
            cf.finish()?;
            cohorts.push(CohortAssignment { cohort, generation });
        }
        if cohorts.iter().map(|c| c.cohort.as_str()).collect::<std::collections::BTreeSet<_>>().len() != cohorts.len() {
            return Err(unknown("a cohort is listed once"));
        }
        let serial = match f.take_opt("serial") {
            None => None,
            Some(Value::Text(t)) => Some(t),
            Some(_) => return Err(unknown("serial is not text")),
        };
        let issued_at = AuthorityTime(f.uint("issued")?);
        let policy = ContentAddress::from(f.bytes_n::<32>("policy")?);
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let signature = signature(&mut f)?;
        f.finish()?;
        Ok(Self { tenancy, collector, handle, keys, agreement_key, record_key, window, cohorts, serial, issued_at, policy, signer, signature })
    }

    /// Decodes canonical CBOR.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode_limited(input, MAX_REQUEST)?)
    }

    /// The runtime's check before using a certificate (REG-033): the signature verifies by
    /// a `registration` key whose chain reaches a root of `bundle`, at the issue time, and
    /// the tenancy is the SHA-256 of the first signing key.
    pub fn verify(&self, bundle: &TrustBundle) -> Result<(), TrustError> {
        TrustStore::new(bundle).verify_signature(
            &self.signer,
            &[],
            &tags::TENANCY_CERTIFICATE,
            &self.signed_structure(),
            &self.signature,
            self.issued_at,
        )?;
        let first = self.keys.iter().find(|k| k.index == 0).ok_or(TrustError::Wire(unknown("no key with index 0")))?;
        if sha256(first.public_key.as_bytes()).as_bytes() != self.tenancy.as_bytes() {
            return Err(TrustError::Wire(WireError::new(ErrorCode::Hash, 0, "tenancy is not SHA-256 of key 0")));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Close and reset certificates (WIRE-141, WIRE-144).

/// The factory's signed instruction to close a tenancy (REG-064): a reset certificate when
/// the reason is `forgotten-pin` (REG-065).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CloseCertificate {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The highest `seq` the authority has received; records above it are flagged.
    pub cutoff: Seq,
    /// Why.
    pub reason: CloseReason,
    /// When it was issued.
    pub issued_at: AuthorityTime,
    /// The registration key that signed it.
    pub signer: KeyId,
    /// The signature.
    pub signature: Signature,
}

impl CloseCertificate {
    /// The domain tag: reset for `forgotten-pin`, close otherwise.
    pub fn tag(reason: CloseReason) -> DomainTag {
        if reason.is_reset() { tags::RESET_CERTIFICATE } else { tags::CLOSE_CERTIFICATE }
    }

    /// The signed structure.
    pub fn signed_structure(&self) -> Value {
        cbor::map([
            ("v", uint(1)),
            ("tenancy", bytes(self.tenancy.as_bytes())),
            ("cutoff_seq", uint(self.cutoff.0)),
            ("reason", text_value(self.reason.as_str())),
            ("issued", uint(self.issued_at.0)),
            ("signer", bytes(self.signer.as_bytes())),
        ])
    }

    /// Canonical CBOR, at most 300 bytes (WIRE-144).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        encode_limited(&with_sig(self.signed_structure(), &self.signature), text::MAX_QR_OBJECT)
    }

    /// Decodes canonical CBOR.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode_limited(input, text::MAX_QR_OBJECT)?)?;
        version(&mut f)?;
        let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
        let cutoff = Seq(f.uint("cutoff_seq")?);
        let reason = CloseReason::parse(&f.text("reason")?).ok_or(unknown("unknown close reason"))?;
        let issued_at = AuthorityTime(f.uint("issued")?);
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let signature = signature(&mut f)?;
        f.finish()?;
        Ok(Self { tenancy, cutoff, reason, issued_at, signer, signature })
    }

    /// The text form `FS1C:…` (WIRE-144), for a QR code.
    pub fn to_text(&self) -> Result<String, WireError> {
        Ok(text::encode(text::CLOSE_PREFIX, &self.encode()?))
    }

    /// Reads the text form.
    pub fn from_text(input: &str) -> Result<Self, WireError> {
        Self::decode(&text::decode(text::CLOSE_PREFIX, input)?)
    }

    /// Verifies the signature to `bundle`, at the issue time.
    pub fn verify(&self, bundle: &TrustBundle) -> Result<(), TrustError> {
        TrustStore::new(bundle)
            .verify_signature(&self.signer, &[], &Self::tag(self.reason), &self.signed_structure(), &self.signature, self.issued_at)
            .map(|_| ())
    }
}

// ---------------------------------------------------------------------------------------
// Posture reports (REG-080).

/// The body of a posture report, as the device builds it. The proof of possession is the
/// signing key's signature over `{nonce, body_sha256}` under the registration PoP tag.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PostureBody {
    /// The tenancy reporting.
    pub tenancy: TenancyId,
    /// The factory's posture nonce.
    pub nonce: Nonce,
    /// The device-policy mode.
    pub mode: ManagementMode,
    /// The effective restrictions.
    pub restrictions: BTreeMap<String, ReportedRestriction>,
    /// Fresh evidence for the signing key over the nonce, if the platform can make it.
    pub evidence: Option<AttestationEvidence>,
}

impl PostureBody {
    /// The body as a value.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("v".to_owned(), uint(1));
        m.insert("tenancy".to_owned(), bytes(self.tenancy.as_bytes()));
        m.insert("nonce".to_owned(), bytes(self.nonce.as_bytes()));
        m.insert("mode".to_owned(), text_value(self.mode.as_str()));
        m.insert(
            "restrictions".to_owned(),
            Value::Map(self.restrictions.iter().map(|(k, v)| (k.clone(), text_value(v.as_str()))).collect()),
        );
        if let Some(e) = &self.evidence {
            m.insert("evidence".to_owned(), cbor::map([("format", text_value(&e.format)), ("data", bytes(&e.data))]));
        }
        Value::Map(m)
    }

    /// SHA-256 of the canonical body.
    pub fn digest(&self) -> Digest {
        sha256(&cbor::encode(&self.to_value()).expect("encodable"))
    }

    /// The message the signing key signs.
    pub fn pop_message(&self) -> Vec<u8> {
        pop_message(&self.nonce, &self.digest())
    }

    /// The report `{body, pop}` as canonical CBOR.
    pub fn encode_report(&self, pop: &Signature) -> Vec<u8> {
        cbor::encode(&cbor::map([("body", self.to_value()), ("pop", bytes(&pop.0))])).expect("encodable")
    }
}

/// Decodes a posture report `{body, pop}`.
pub fn decode_posture(input: &[u8]) -> Result<PostureReport, WireError> {
    let mut f = Fields::new(cbor::decode_limited(input, MAX_POSTURE_REPORT)?)?;
    let mut b = Fields::new(f.take("body")?)?;
    version(&mut b)?;
    let tenancy = TenancyId::from(b.bytes_n::<32>("tenancy")?);
    let nonce = Nonce::from(b.bytes_n::<32>("nonce")?);
    let mode = ManagementMode::parse(&b.text("mode")?).ok_or(unknown("unknown management mode"))?;
    let restrictions = match b.take("restrictions")? {
        Value::Map(m) => m
            .into_iter()
            .map(|(k, v)| match v {
                _ if k.is_empty() => Err(unknown("a restriction is named")),
                Value::Text(t) => ReportedRestriction::parse(&t).map(|r| (k, r)).ok_or(unknown("unknown restriction state")),
                _ => Err(unknown("restriction state is not text")),
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?,
        _ => return Err(unknown("restrictions is not a map")),
    };
    let evidence = match b.take_opt("evidence") {
        None => None,
        Some(v) => {
            let mut ef = Fields::new(v)?;
            let format = ef.text("format")?;
            let data = ef.bytes("data")?;
            ef.finish()?;
            if format.is_empty() {
                return Err(unknown("an evidence format is named"));
            }
            Some(AttestationEvidence { format, data })
        }
    };
    b.finish()?;
    let pop = Signature(f.bytes_n::<64>("pop")?.to_vec());
    f.finish()?;
    let body = PostureBody { tenancy, nonce, mode, restrictions, evidence };
    Ok(PostureReport {
        body_digest: body.digest(),
        tenancy,
        nonce,
        mode,
        restrictions: body.restrictions,
        evidence: body.evidence,
        proof_of_possession: pop,
    })
}

// ---------------------------------------------------------------------------------------
// Small helpers shared by adapters.

pub use fieldseal_kernel::base64url::{base64url_decode, base64url_encode};
pub use fieldseal_kernel::pop::{MAX_POP_TOKEN, POP_HEADER, PopToken};

/// The factory key a device seals its request to (WIRE-134): the X25519 `registration` key
/// certified in the device's trust bundle, valid at `at`.
pub fn factory_sealing_key(bundle: &TrustBundle, at: AuthorityTime) -> Option<RecipientKey> {
    let store = TrustStore::new(bundle);
    bundle.certificates().iter().find_map(|c| match c.public_key() {
        fieldseal_trust::domain::AuthorityPublicKey::X25519(k)
            if c.purpose() == Some(fieldseal_kernel::crypto::Purpose::Registration) && store.verify_certificate(c, at).is_ok() =>
        {
            Some(RecipientKey::X25519(*k))
        }
        _ => None,
    })
}

/// The key ID of a device signing key (WIRE-010).
pub fn device_key_id(key: &P256PublicKey) -> KeyId {
    key_id(key.as_bytes())
}

/// Reads an unsigned integer from a value (for adapters decoding small structures).
pub fn value_uint(v: Value) -> Result<u64, WireError> {
    expect_uint(v)
}
