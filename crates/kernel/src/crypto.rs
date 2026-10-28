//! Cryptographic value types. The operations themselves are in the format core
//! (issue #42) or behind key-custody ports; these are only the values passed around.

use crate::KernelError;

/// The purposes an authority key can be certified for (TRU §6.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Purpose {
    /// Signs bundles.
    Factory,
    /// Registration tokens, tenancy, close and reset certificates.
    Registration,
    /// Artefact signatures.
    Publisher,
    /// Provenance statements.
    Builder,
    /// Receipts and time tokens.
    Receipt,
    /// Proves a destination may receive uploads (ADR 0021).
    Receiver,
    /// Decrypts records for one collection period.
    Record,
}

impl Purpose {
    /// Every purpose, in the order of TRU §6.1.
    pub const ALL: [Purpose; 7] = [
        Purpose::Factory,
        Purpose::Registration,
        Purpose::Publisher,
        Purpose::Builder,
        Purpose::Receipt,
        Purpose::Receiver,
        Purpose::Record,
    ];

    /// The purpose's name as written in TRU §6.1 and in key certificates, for example `factory`.
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Factory => "factory",
            Purpose::Registration => "registration",
            Purpose::Publisher => "publisher",
            Purpose::Builder => "builder",
            Purpose::Receipt => "receipt",
            Purpose::Receiver => "receiver",
            Purpose::Record => "record",
        }
    }

    /// Parses a purpose name; `None` for any other text (including `log`, which is not an
    /// authority key).
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == text)
    }
}

/// A domain tag, `fieldseal.dev/<purpose>/<version>`, prefixed to every signed message.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct DomainTag(&'static str);

impl DomainTag {
    /// Wraps a tag; it must start with `fieldseal.dev/`.
    pub const fn new(tag: &'static str) -> Self {
        Self(tag)
    }

    /// The tag text.
    pub fn as_str(&self) -> &'static str {
        self.0
    }

    /// What the tag binds, if it is one of the tags of WIRE §6.1 (and the tags named in
    /// WIRE-170, WIRE-181 and WIRE-190); `None` for any other text.
    pub fn usage(&self) -> Option<TagUsage> {
        KNOWN_TAGS.iter().find(|(t, _)| t.0 == self.0).map(|(_, u)| *u)
    }

    /// Looks up a known tag by its text, rejecting any other with `E_TAG` (WIRE-020).
    pub fn known(text: &str) -> Result<Self, crate::error::WireError> {
        KNOWN_TAGS
            .iter()
            .find(|(t, _)| t.0 == text)
            .map(|(t, _)| t.clone())
            .ok_or(crate::error::WireError::new(crate::error::ErrorCode::Tag, 0, "unknown domain tag"))
    }

    /// Checks that the tag is known and is meant for `usage`, else `E_TAG` (WIRE-020).
    pub fn expect(&self, usage: TagUsage) -> Result<(), crate::error::WireError> {
        if self.usage() == Some(usage) {
            Ok(())
        } else {
            Err(crate::error::WireError::new(crate::error::ErrorCode::Tag, 0, "unknown or unexpected domain tag"))
        }
    }
}

/// What a domain tag is bound to (WIRE-020).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TagUsage {
    /// An ECDSA signature (WIRE-021).
    Signature,
    /// An HPKE seal's `info` (WIRE-023).
    Seal,
    /// An AEAD's additional data (WIRE-081).
    Aead,
}

/// The domain tags of WIRE §6.1 and the protocol messages, as constants.
pub mod tags {
    use super::DomainTag;

    /// Record signature (WIRE-037).
    pub const RECORD: DomainTag = DomainTag::new("fieldseal.dev/record/v1");
    /// Record payload seal (WIRE-038).
    pub const RECORD_SEAL: DomainTag = DomainTag::new("fieldseal.dev/record-seal/v1");
    /// Local record AEAD context (WIRE-081).
    pub const LOCAL_RECORD: DomainTag = DomainTag::new("fieldseal.dev/local-record/v1");
    /// Bundle signature (WIRE-092).
    pub const BUNDLE: DomainTag = DomainTag::new("fieldseal.dev/bundle/v1");
    /// Bundle seal (WIRE-091).
    pub const BUNDLE_SEAL: DomainTag = DomainTag::new("fieldseal.dev/bundle-seal/v1");
    /// Export signature (WIRE-106).
    pub const EXPORT: DomainTag = DomainTag::new("fieldseal.dev/export/v1");
    /// Export manifest seal (WIRE-103).
    pub const EXPORT_MANIFEST_SEAL: DomainTag = DomainTag::new("fieldseal.dev/export-manifest-seal/v1");
    /// Registration token signature (WIRE-120).
    pub const REGISTRATION_TOKEN: DomainTag = DomainTag::new("fieldseal.dev/registration-token/v1");
    /// Registration proof of possession (WIRE-132).
    pub const REGISTRATION_POP: DomainTag = DomainTag::new("fieldseal.dev/registration-pop/v1");
    /// Registration request seal (WIRE-134).
    pub const REGISTRATION_SEAL: DomainTag = DomainTag::new("fieldseal.dev/registration-seal/v1");
    /// Tenancy certificate (WIRE-140).
    pub const TENANCY_CERTIFICATE: DomainTag = DomainTag::new("fieldseal.dev/tenancy-certificate/v1");
    /// Close certificate (WIRE-141).
    pub const CLOSE_CERTIFICATE: DomainTag = DomainTag::new("fieldseal.dev/close-certificate/v1");
    /// Reset certificate (WIRE-141).
    pub const RESET_CERTIFICATE: DomainTag = DomainTag::new("fieldseal.dev/reset-certificate/v1");
    /// Receipt (WIRE-142).
    pub const RECEIPT: DomainTag = DomainTag::new("fieldseal.dev/receipt/v1");
    /// Time token (WIRE-143).
    pub const TIME_TOKEN: DomainTag = DomainTag::new("fieldseal.dev/time-token/v1");
    /// Key certificate (Trust).
    pub const KEY_CERTIFICATE: DomainTag = DomainTag::new("fieldseal.dev/key-certificate/v1");
    /// Trust bundle (Trust).
    pub const TRUST_BUNDLE: DomainTag = DomainTag::new("fieldseal.dev/trust-bundle/v1");
    /// Root revocation (Trust, TRU-040).
    pub const REVOCATION: DomainTag = DomainTag::new("fieldseal.dev/revocation/v1");
    /// A certificate request's proof of possession, by the requested key (Trust, TRU-016).
    pub const CSR: DomainTag = DomainTag::new("fieldseal.dev/csr/v1");
    /// Artefact signature (Publishing).
    pub const ARTEFACT: DomainTag = DomainTag::new("fieldseal.dev/artefact/v1");
    /// Provenance statement (Publishing).
    pub const PROVENANCE: DomainTag = DomainTag::new("fieldseal.dev/provenance/v1");
    /// Log tree head (Publishing).
    pub const TREE_HEAD: DomainTag = DomainTag::new("fieldseal.dev/tree-head/v1");
    /// Withdrawal (Publishing).
    pub const WITHDRAWAL: DomainTag = DomainTag::new("fieldseal.dev/withdrawal/v1");
    /// API proof-of-possession token (WIRE-170).
    pub const API_POP: DomainTag = DomainTag::new("fieldseal.dev/api-pop/v1");
    /// Receiver challenge answer (WIRE-181).
    pub const RECEIVER_CHALLENGE: DomainTag = DomainTag::new("fieldseal.dev/receiver-challenge/v1");
    /// Publication statement (WIRE-190).
    pub const PUBLICATION: DomainTag = DomainTag::new("fieldseal.dev/publication/v1");
}

const KNOWN_TAGS: &[(DomainTag, TagUsage)] = &[
    (tags::RECORD, TagUsage::Signature),
    (tags::RECORD_SEAL, TagUsage::Seal),
    (tags::LOCAL_RECORD, TagUsage::Aead),
    (tags::BUNDLE, TagUsage::Signature),
    (tags::BUNDLE_SEAL, TagUsage::Seal),
    (tags::EXPORT, TagUsage::Signature),
    (tags::EXPORT_MANIFEST_SEAL, TagUsage::Seal),
    (tags::REGISTRATION_TOKEN, TagUsage::Signature),
    (tags::REGISTRATION_POP, TagUsage::Signature),
    (tags::REGISTRATION_SEAL, TagUsage::Seal),
    (tags::TENANCY_CERTIFICATE, TagUsage::Signature),
    (tags::CLOSE_CERTIFICATE, TagUsage::Signature),
    (tags::RESET_CERTIFICATE, TagUsage::Signature),
    (tags::RECEIPT, TagUsage::Signature),
    (tags::TIME_TOKEN, TagUsage::Signature),
    (tags::KEY_CERTIFICATE, TagUsage::Signature),
    (tags::TRUST_BUNDLE, TagUsage::Signature),
    (tags::REVOCATION, TagUsage::Signature),
    (tags::CSR, TagUsage::Signature),
    (tags::ARTEFACT, TagUsage::Signature),
    (tags::PROVENANCE, TagUsage::Signature),
    (tags::TREE_HEAD, TagUsage::Signature),
    (tags::WITHDRAWAL, TagUsage::Signature),
    (tags::API_POP, TagUsage::Signature),
    (tags::RECEIVER_CHALLENGE, TagUsage::Signature),
    (tags::PUBLICATION, TagUsage::Signature),
];

/// A P-256 public key in uncompressed SEC1 form.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct P256PublicKey([u8; 65]);

impl P256PublicKey {
    /// Wraps 65 bytes beginning with `0x04` that encode a point on the P-256 curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KernelError> {
        let array: [u8; 65] = bytes.try_into().map_err(|_| KernelError::Length {
            kind: "P256PublicKey",
            expected: 65,
            actual: bytes.len(),
        })?;
        if array[0] != 0x04 {
            return Err(KernelError::Malformed { kind: "P256PublicKey", reason: "not uncompressed SEC1" });
        }
        // The point MUST lie on the curve (and not be the identity): SEC1 decoding checks it.
        if p256::PublicKey::from_sec1_bytes(&array).is_err() {
            return Err(KernelError::Malformed { kind: "P256PublicKey", reason: "point is not on the P-256 curve" });
        }
        Ok(Self(array))
    }

    /// The SEC1 bytes.
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

/// Checks that 32 bytes are an X25519 public key that is safe to agree with: the all-zero
/// point and every other small-order point (whose Diffie-Hellman output is all zeros) are
/// refused, as RFC 9180 §7.1.4 requires (WIRE-009).
pub fn check_x25519_public(key: &[u8; 32]) -> Result<(), KernelError> {
    use hpke::{Deserializable, Kem};
    let bad = KernelError::Malformed { kind: "X25519PublicKey", reason: "small-order point" };
    let pk = <hpke::kem::X25519HkdfSha256 as Kem>::PublicKey::from_bytes(key).map_err(|_| bad.clone())?;
    // A small-order point gives an all-zero shared secret for every scalar, which HPKE's
    // encapsulation refuses; any fixed ephemeral key therefore decides it.
    hpke::setup_sender_with_rng::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
        &hpke::OpModeS::Base,
        &pk,
        b"",
        &mut FixedRng(0x9e37_79b9_7f4a_7c15),
    )
    .map(|_| ())
    .map_err(|_| bad)
}

/// A deterministic generator used only to probe a key: it protects nothing.
struct FixedRng(u64);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        Ok(self.0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let b = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for FixedRng {}

/// An ECDSA P-256 signature: 64 bytes `r ‖ s` with low `s` (WIRE-022). See [`crate::sign`].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Signature(pub Vec<u8>);

/// A sealed (encrypted) payload addressed to one recipient key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sealed(pub Vec<u8>);
