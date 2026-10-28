//! HPKE seals (WIRE-023..026): RFC 9180 base mode with `info` set to the domain tag.
//!
//! | Suite | KEM | KDF | AEAD | Recipient |
//! |---|---|---|---|---|
//! | `fs1-x` | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 | authority keys |
//! | `fs1-p` | DHKEM(P-256, HKDF-SHA256) | HKDF-SHA256 | AES-256-GCM | device agreement keys |
//!
//! The kernel never reads randomness itself: [`seal`] takes the ephemeral key's randomness
//! from the caller's [`CryptoRng`]. HPKE's shared secrets and derived keys are zeroised by the
//! HPKE implementation when dropped, and opened plaintext is returned in [`Zeroizing`].

use hpke::aead::{AesGcm256, ChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::kem::{DhP256HkdfSha256, X25519HkdfSha256};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::cbor;
use crate::crypto::{DomainTag, P256PublicKey, TagUsage};
use crate::digest::key_id;
use crate::error::{ErrorCode, KernelError, WireError};
use crate::id::KeyId;
use crate::value::Value;

/// A sealing suite (WIRE-023).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Suite {
    /// `fs1-x`: X25519, HKDF-SHA256, ChaCha20-Poly1305. For authority record and registration keys.
    Fs1X,
    /// `fs1-p`: P-256, HKDF-SHA256, AES-256-GCM. For device agreement keys.
    Fs1P,
}

impl Suite {
    /// The suite ID as written on the wire.
    pub fn id(self) -> &'static str {
        match self {
            Suite::Fs1X => "fs1-x",
            Suite::Fs1P => "fs1-p",
        }
    }

    /// Parses a suite ID, refusing any other with `E_SUITE`.
    pub fn parse(id: &str) -> Result<Self, WireError> {
        match id {
            "fs1-x" => Ok(Suite::Fs1X),
            "fs1-p" => Ok(Suite::Fs1P),
            _ => Err(WireError::new(ErrorCode::Suite, 0, "unknown suite")),
        }
    }
}

/// A recipient's public key, which fixes the suite.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RecipientKey {
    /// An authority X25519 key (32 raw bytes, WIRE-009).
    X25519([u8; 32]),
    /// A device P-256 agreement key.
    P256(P256PublicKey),
}

impl RecipientKey {
    /// An X25519 recipient key from 32 raw bytes, refusing small-order points (WIRE-009).
    pub fn x25519(bytes: &[u8]) -> Result<Self, KernelError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KernelError::Length { kind: "X25519PublicKey", expected: 32, actual: bytes.len() })?;
        crate::crypto::check_x25519_public(&array)?;
        Ok(RecipientKey::X25519(array))
    }

    /// The suite used to seal to this key.
    pub fn suite(&self) -> Suite {
        match self {
            RecipientKey::X25519(_) => Suite::Fs1X,
            RecipientKey::P256(_) => Suite::Fs1P,
        }
    }

    /// The key's encoding (WIRE-009).
    pub fn encoded(&self) -> &[u8] {
        match self {
            RecipientKey::X25519(k) => k,
            RecipientKey::P256(k) => k.as_bytes(),
        }
    }

    /// The key's identifier (WIRE-010).
    pub fn key_id(&self) -> KeyId {
        key_id(self.encoded())
    }
}

/// A recipient's private key, held in software and zeroised on drop.
pub enum RecipientSecret {
    /// An X25519 private key.
    X25519(Zeroizing<[u8; 32]>),
    /// A P-256 private scalar.
    P256(Zeroizing<[u8; 32]>),
}

impl RecipientSecret {
    /// Imports 32 private-key bytes for the suite's KEM.
    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<Self, KernelError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KernelError::Length { kind: "RecipientSecret", expected: 32, actual: bytes.len() })?;
        let secret = match suite {
            Suite::Fs1X => RecipientSecret::X25519(Zeroizing::new(array)),
            Suite::Fs1P => RecipientSecret::P256(Zeroizing::new(array)),
        };
        secret.public().map(|_| secret)
    }

    /// Generates a key from the caller's cryptographically secure random source.
    pub fn generate(suite: Suite, rng: &mut impl CryptoRng) -> Self {
        match suite {
            Suite::Fs1X => {
                let (sk, _) = X25519HkdfSha256::gen_keypair_with_rng(rng);
                RecipientSecret::X25519(Zeroizing::new(sk.to_bytes().into()))
            }
            Suite::Fs1P => {
                let (sk, _) = DhP256HkdfSha256::gen_keypair_with_rng(rng);
                RecipientSecret::P256(Zeroizing::new(sk.to_bytes().into()))
            }
        }
    }

    /// The suite this key accepts.
    pub fn suite(&self) -> Suite {
        match self {
            RecipientSecret::X25519(_) => Suite::Fs1X,
            RecipientSecret::P256(_) => Suite::Fs1P,
        }
    }

    /// The matching public key.
    pub fn public(&self) -> Result<RecipientKey, KernelError> {
        let bad = KernelError::Malformed { kind: "RecipientSecret", reason: "not a valid private key" };
        match self {
            RecipientSecret::X25519(b) => {
                let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&b[..]).map_err(|_| bad.clone())?;
                let pk = X25519HkdfSha256::sk_to_pk(&sk);
                Ok(RecipientKey::X25519(pk.to_bytes().into()))
            }
            RecipientSecret::P256(b) => {
                let sk = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&b[..]).map_err(|_| bad.clone())?;
                let pk = DhP256HkdfSha256::sk_to_pk(&sk);
                let p = P256PublicKey::from_bytes(&pk.to_bytes()).map_err(|_| bad)?;
                Ok(RecipientKey::P256(p))
            }
        }
    }
}

/// A `Sealed<T>`: `{"suite", "recipient", "enc", "ct"}` (WIRE-024).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedBox {
    /// The suite.
    pub suite: Suite,
    /// The recipient's key ID.
    pub recipient: KeyId,
    /// The HPKE encapsulated key.
    pub enc: Vec<u8>,
    /// The ciphertext with its AEAD tag.
    pub ct: Vec<u8>,
}

impl SealedBox {
    /// The structure as a value.
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("suite", Value::Text(self.suite.id().to_owned())),
            ("recipient", Value::Bytes(self.recipient.as_bytes().to_vec())),
            ("enc", Value::Bytes(self.enc.clone())),
            ("ct", Value::Bytes(self.ct.clone())),
        ])
    }

    /// Reads the structure from a value, refusing any other key with `E_UNKNOWN_FIELD`
    /// and an unknown suite with `E_SUITE`.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = crate::structure::Fields::new(value)?;
        let suite = Suite::parse(&f.text("suite")?)?;
        let recipient = KeyId::from(f.bytes_n::<16>("recipient")?);
        let enc = f.bytes("enc")?;
        let ct = f.bytes("ct")?;
        f.finish()?;
        let enc_len = match suite {
            Suite::Fs1X => 32,
            Suite::Fs1P => 65,
        };
        if enc.len() != enc_len {
            return Err(WireError::new(ErrorCode::UnknownField, 0, "enc is not an encapsulated key of the suite's size"));
        }
        Ok(Self { suite, recipient, enc, ct })
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a sealed box is always encodable")
    }

    /// Decodes canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}

/// Seals `plaintext` to `recipient` under `tag` (WIRE-023): base mode, `info` = the tag's
/// UTF-8 bytes, empty AAD. The tag must be a known seal tag (`E_TAG`).
pub fn seal(rng: &mut impl CryptoRng, recipient: &RecipientKey, tag: &DomainTag, plaintext: &[u8]) -> Result<SealedBox, WireError> {
    seal_with_context(rng, recipient, tag, &[], plaintext)
}

/// The HPKE `info` for a seal: the tag's UTF-8 bytes, and, when `context` is not empty, a
/// zero byte and the context (DIS-020 binds a bundle to its tenancy ID this way). An empty
/// context gives exactly the info of [`seal`].
pub fn seal_info(tag: &DomainTag, context: &[u8]) -> Vec<u8> {
    let mut info = tag.as_str().as_bytes().to_vec();
    if !context.is_empty() {
        info.push(0);
        info.extend_from_slice(context);
    }
    info
}

/// Seals `plaintext` to `recipient` under `tag` with `context` bound into the HPKE `info`
/// (see [`seal_info`]). A seal made with one context does not open under another.
pub fn seal_with_context(
    rng: &mut impl CryptoRng,
    recipient: &RecipientKey,
    tag: &DomainTag,
    context: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox, WireError> {
    tag.expect(TagUsage::Seal)?;
    let info = seal_info(tag, context);
    let info = info.as_slice();
    let fail = |_| WireError::new(ErrorCode::Decrypt, 0, "HPKE encapsulation failed");
    let (enc, ct) = match recipient {
        RecipientKey::X25519(pk) => {
            let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(pk).map_err(fail)?;
            let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                &pk,
                info,
                plaintext,
                &[],
                rng,
            )
            .map_err(fail)?;
            (enc.to_bytes().to_vec(), ct)
        }
        RecipientKey::P256(pk) => {
            let pk = <DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(pk.as_bytes()).map_err(fail)?;
            let (enc, ct) = hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
                &OpModeS::Base,
                &pk,
                info,
                plaintext,
                &[],
                rng,
            )
            .map_err(fail)?;
            (enc.to_bytes().to_vec(), ct)
        }
    };
    Ok(SealedBox { suite: recipient.suite(), recipient: recipient.key_id(), enc, ct })
}

/// Seals a value's canonical CBOR.
pub fn seal_value(rng: &mut impl CryptoRng, recipient: &RecipientKey, tag: &DomainTag, value: &Value) -> Result<SealedBox, WireError> {
    let plaintext = Zeroizing::new(cbor::encode(value)?);
    seal(rng, recipient, tag, &plaintext)
}

/// Opens a seal with the recipient's own key. Checks, in order: the tag is a known seal tag
/// (`E_TAG`), the suite is the one for this key type (`E_SUITE`), the recipient is this key
/// (`E_RECIPIENT`), then decapsulates and decrypts (`E_DECRYPT`).
pub fn open(secret: &RecipientSecret, tag: &DomainTag, sealed: &SealedBox) -> Result<Zeroizing<Vec<u8>>, WireError> {
    open_with_context(secret, tag, &[], sealed)
}

/// [`open`] for a seal made with [`seal_with_context`] and the same `context`.
pub fn open_with_context(
    secret: &RecipientSecret,
    tag: &DomainTag,
    context: &[u8],
    sealed: &SealedBox,
) -> Result<Zeroizing<Vec<u8>>, WireError> {
    tag.expect(TagUsage::Seal)?;
    if sealed.suite != secret.suite() {
        return Err(WireError::new(ErrorCode::Suite, 0, "suite not expected for this key type"));
    }
    let own = secret.public().map_err(|_| WireError::new(ErrorCode::Decrypt, 0, "invalid private key"))?;
    if sealed.recipient != own.key_id() {
        return Err(WireError::new(ErrorCode::Recipient, 0, "sealed to another key"));
    }
    let info = seal_info(tag, context);
    let info = info.as_slice();
    let fail = |_| WireError::new(ErrorCode::Decrypt, 0, "HPKE open failed");
    let plaintext = match secret {
        RecipientSecret::X25519(b) => {
            let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&b[..]).map_err(fail)?;
            let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&sealed.enc).map_err(fail)?;
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, &sk, &enc, info, &sealed.ct, &[])
                .map_err(fail)?
        }
        RecipientSecret::P256(b) => {
            let sk = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&b[..]).map_err(fail)?;
            let enc = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(&sealed.enc).map_err(fail)?;
            hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(&OpModeR::Base, &sk, &enc, info, &sealed.ct, &[])
                .map_err(fail)?
        }
    };
    Ok(Zeroizing::new(plaintext))
}

/// Opens a seal and decodes its plaintext as canonical CBOR.
pub fn open_value(secret: &RecipientSecret, tag: &DomainTag, sealed: &SealedBox) -> Result<Value, WireError> {
    cbor::decode(&open(secret, tag, sealed)?)
}
