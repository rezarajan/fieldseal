//! The time token (WIRE §6.6): an authority-signed statement of the time, which a bundle
//! carries as its fresh anchor (DIS-010).

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{Signature, tags};
use fieldseal_kernel::error::{ErrorCode, WireError};
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_publishing::domain::verify::check_tree_head_age;
use fieldseal_publishing::domain::{Publication, PublishingError};
use fieldseal_trust::domain::{TrustError, TrustStore};

/// What kind of time statement an anchor is (WIRE-057).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AnchorKind {
    /// The runtime build's release anchor.
    Build,
    /// A bundle's issue time.
    Bundle,
    /// A receipt.
    Receipt,
    /// A time token.
    TimeToken,
}

/// The tree-head age check of PUB-072 for one publication a runtime or factory consumes.
///
/// C2SP checkpoints carry no time, so the age is measured from the authority time token
/// that accompanied the checkpoint when it was obtained (`publication.checkpoint_time`,
/// verified here against `store`) to the bundle's own time token (`bundle_time`). A tree
/// head with no token, or a token that is malformed or not authentic, is too old. `max_age_ms`
/// is `runtime.publishing.maxTreeHeadAge` in milliseconds.
pub fn check_publication_tree_head_age(
    publication: &Publication,
    bundle_time: AuthorityTime,
    store: &TrustStore<'_>,
    max_age_ms: u64,
) -> Result<(), PublishingError> {
    let tree_head_time = match &publication.checkpoint_time {
        None => None,
        Some(bytes) => {
            let invalid = |e: String| PublishingError::CheckpointTime(e);
            let token = TimeToken::decode(bytes).map_err(|e| invalid(e.to_string()))?;
            token.verify(store).map_err(|e| invalid(e.to_string()))?;
            Some(token.authority_time)
        }
    };
    check_tree_head_age(tree_head_time, bundle_time, max_age_ms)
}

/// The limit on a time token's canonical CBOR (WIRE §6.7).
pub const MAX_TIME_TOKEN: usize = 300;

/// An authority time statement signed by the receipt-and-time key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TimeToken {
    /// The authority time it states.
    pub authority_time: AuthorityTime,
    /// The requester's nonce, if it asked with one.
    pub nonce: Option<[u8; 16]>,
    /// The key that signed it.
    pub signer: KeyId,
    /// The signature over tag `fieldseal.dev/time-token/v1`.
    pub signature: Signature,
}

impl TimeToken {
    /// The signed structure: the token without `sig`.
    pub fn signed_structure(&self) -> Value {
        let mut fields = vec![
            ("v", Value::Int(1)),
            ("authority_time", Value::Int(i128::from(self.authority_time.0))),
            ("signer", Value::Bytes(self.signer.as_bytes().to_vec())),
        ];
        if let Some(n) = &self.nonce {
            fields.push(("nonce", Value::Bytes(n.to_vec())));
        }
        cbor::map(fields)
    }

    /// The whole token as a value.
    pub fn to_value(&self) -> Value {
        let Value::Map(mut m) = self.signed_structure() else { unreachable!("a structure is a map") };
        m.insert("sig".to_owned(), Value::Bytes(self.signature.0.clone()));
        Value::Map(m)
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a time token is encodable")
    }

    /// Strictly reads a token.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        f.version("v", &Value::Int(1))?;
        let authority_time = AuthorityTime(f.uint("authority_time")?);
        let nonce = match f.take_opt("nonce") {
            None => None,
            Some(v) => Some(fieldseal_kernel::structure::expect_bytes_n::<16>(v)?),
        };
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let signature = Signature(f.bytes("sig")?);
        f.finish()?;
        let token = Self { authority_time, nonce, signer, signature };
        if token.encode().len() > MAX_TIME_TOKEN {
            return Err(WireError::new(ErrorCode::Size, 0, "time token exceeds its size limit"));
        }
        Ok(token)
    }

    /// Decodes canonical CBOR, refusing input over the size limit before parsing.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode_limited(bytes, MAX_TIME_TOKEN)?)
    }

    /// The text form `FS1N:…` for a QR code (WIRE-144).
    pub fn to_text(&self) -> String {
        fieldseal_kernel::text::encode(fieldseal_kernel::text::TIME_TOKEN_PREFIX, &self.encode())
    }

    /// Reads the text form.
    pub fn from_text(input: &str) -> Result<Self, WireError> {
        Self::decode(&fieldseal_kernel::text::decode(fieldseal_kernel::text::TIME_TOKEN_PREFIX, input)?)
    }

    /// Verifies the signature: a `receipt` key whose chain reaches a root of the store's
    /// bundle, valid at the time the token states.
    pub fn verify(&self, store: &TrustStore<'_>) -> Result<(), TrustError> {
        store
            .verify_signature(&self.signer, &[], &tags::TIME_TOKEN, &self.signed_structure(), &self.signature, self.authority_time)
            .map(|_| ())
    }
}
