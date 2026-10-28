//! Small helpers shared by the Trust structures' encoders and decoders.

use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value, WireError};

/// The structure's version field, `"v": 1` (WIRE-150).
pub(crate) const V1: Value = Value::Int(1);

/// A structure that is not the one its version defines (WIRE-005).
pub(crate) fn not_defined(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

pub(crate) fn uint(n: u64) -> Value {
    Value::Int(i128::from(n))
}

pub(crate) fn time(t: AuthorityTime) -> Value {
    uint(t.0)
}

pub(crate) fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

pub(crate) fn text(t: &str) -> Value {
    Value::Text(t.to_owned())
}

pub(crate) fn key_id(f: &mut Fields, key: &str) -> Result<KeyId, WireError> {
    Ok(KeyId::from(f.bytes_n::<16>(key)?))
}

pub(crate) fn signature(f: &mut Fields, key: &str) -> Result<Signature, WireError> {
    Ok(Signature(f.bytes_n::<64>(key)?.to_vec()))
}

pub(crate) fn auth_time(f: &mut Fields, key: &str) -> Result<AuthorityTime, WireError> {
    Ok(AuthorityTime(f.uint(key)?))
}

pub(crate) fn text_value(v: Value) -> Result<String, WireError> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(not_defined("field is not text")),
    }
}

pub(crate) fn map_value(v: Value) -> Result<std::collections::BTreeMap<String, Value>, WireError> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(not_defined("field is not a map")),
    }
}
