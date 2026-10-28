//! Proof-of-possession API tokens (WIRE-170..172).
//!
//! Both the runtime that makes the token (Delivery) and the factory that checks it
//! (Registration) use this codec, so it lives in the kernel rather than in either context.

use std::collections::BTreeMap;

use crate::base64url::{base64url_decode, base64url_encode};
use crate::cbor;
use crate::crypto::{P256PublicKey, Signature, tags};
use crate::error::{ErrorCode, WireError};
use crate::id::{Digest, TenancyId};
use crate::sign;
use crate::structure::{Fields, expect_bytes_n};
use crate::time::AuthorityTime;
use crate::value::Value;

/// The largest proof-of-possession API token.
pub const MAX_POP_TOKEN: usize = 4 * 1024;

/// The HTTP header carrying a PoP token (WIRE-172).
pub const POP_HEADER: &str = "Fieldseal-PoP";

/// A proof-of-possession token for one API request (WIRE-170), signed by the tenancy's
/// current signing key over tag `fieldseal.dev/api-pop/v1`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PopToken {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The HTTP method, upper case.
    pub method: String,
    /// The request URL, without query or fragment (as DPoP's `htu`).
    pub url: String,
    /// When it was made, by the device's clock, in milliseconds.
    pub iat: AuthorityTime,
    /// A unique identifier, for replay detection.
    pub jti: [u8; 16],
    /// SHA-256 of the access token, when one is sent.
    pub ath: Option<Digest>,
    /// The signature.
    pub signature: Signature,
}

impl PopToken {
    /// The signed structure: the token without `sig`.
    pub fn signed_structure(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("v".to_owned(), Value::Int(1));
        m.insert("tenancy".to_owned(), Value::Bytes(self.tenancy.as_bytes().to_vec()));
        m.insert("method".to_owned(), Value::Text(self.method.clone()));
        m.insert("url".to_owned(), Value::Text(self.url.clone()));
        m.insert("iat".to_owned(), Value::Int(i128::from(self.iat.0)));
        m.insert("jti".to_owned(), Value::Bytes(self.jti.to_vec()));
        if let Some(a) = &self.ath {
            m.insert("ath".to_owned(), Value::Bytes(a.as_bytes().to_vec()));
        }
        Value::Map(m)
    }

    /// The message the signing key signs.
    pub fn message(&self) -> Vec<u8> {
        sign::signed_message(&tags::API_POP, &self.signed_structure()).expect("encodable")
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let Value::Map(mut m) = self.signed_structure() else { unreachable!("a structure is a map") };
        m.insert("sig".to_owned(), Value::Bytes(self.signature.0.clone()));
        cbor::encode(&Value::Map(m)).expect("encodable")
    }

    /// Decodes canonical CBOR.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode_limited(input, MAX_POP_TOKEN)?)?;
        f.version("v", &Value::Int(1))?;
        let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
        let method = f.text("method")?;
        let url = f.text("url")?;
        let iat = AuthorityTime(f.uint("iat")?);
        let jti = f.bytes_n::<16>("jti")?;
        let ath = f.take_opt("ath").map(expect_bytes_n::<32>).transpose()?.map(Digest::from);
        let signature = Signature(f.bytes_n::<64>("sig")?.to_vec());
        f.finish()?;
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(WireError::new(ErrorCode::UnknownField, 0, "method is an upper-case HTTP method (WIRE-170)"));
        }
        if url.is_empty() || url.contains(['?', '#']) {
            return Err(WireError::new(ErrorCode::UnknownField, 0, "url has no query or fragment (WIRE-170)"));
        }
        Ok(Self { tenancy, method, url, iat, jti, ath, signature })
    }

    /// The header value: base64url of the canonical CBOR (WIRE-172).
    pub fn to_header(&self) -> String {
        base64url_encode(&self.encode())
    }

    /// Reads a header value.
    pub fn from_header(value: &str) -> Result<Self, WireError> {
        if value.len() > MAX_POP_TOKEN * 2 {
            return Err(WireError::new(ErrorCode::Size, 0, "PoP header too long"));
        }
        Self::decode(&base64url_decode(value.trim())?)
    }

    /// Verifies the signature by `key`.
    pub fn verify_signature(&self, key: &P256PublicKey) -> Result<(), WireError> {
        sign::verify(key, &tags::API_POP, &self.signed_structure(), &self.signature)
    }
}
