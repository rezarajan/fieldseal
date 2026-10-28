//! Python bindings for authority-side tools. An interface adapter (ADR 0028): it only
//! converts types and errors. Use cases are exposed here as each context is implemented.
//!
//! Wire-format failures raise `fieldseal.WireError` (a `ValueError`) whose message starts
//! with the WIRE §6.8 code, and whose `args` are `(code, offset, message)`.

use std::collections::BTreeMap;

use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::{instrument_fingerprint, key_id as wire_key_id};
use fieldseal_kernel::id::{ContentAddress, Salt};
use fieldseal_kernel::{Decimal, Value};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyInt, PyList, PyString, PyTuple};

create_exception!(fieldseal, WireError, PyValueError, "A wire-format failure with a WIRE §6.8 code.");

fn wire_err(e: fieldseal_kernel::WireError) -> PyErr {
    WireError::new_err((e.code.as_str(), e.offset, e.to_string()))
}

fn json_err(detail: impl Into<String>) -> PyErr {
    WireError::new_err(("E_CBOR_NONCANONICAL", 0usize, format!("E_CBOR_NONCANONICAL: {}", detail.into())))
}

/// The version of the Fieldseal core these bindings were built from.
#[pyfunction]
fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The content address of canonical bytes: `sha256:` and 64 lowercase hex digits (WIRE-011).
#[pyfunction]
fn content_address(data: &[u8]) -> String {
    ContentAddress::of(data).to_text()
}

/// The 16-byte key identifier of an encoded public key (WIRE-010).
#[pyfunction]
fn key_id<'py>(py: Python<'py>, public_key: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, wire_key_id(public_key).as_bytes())
}

/// An instrument's 32-byte salted fingerprint (WIRE-185).
#[pyfunction]
fn fingerprint<'py>(py: Python<'py>, salt: &[u8], canonical: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let salt = Salt::from_bytes(salt).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, instrument_fingerprint(&salt, canonical).as_bytes()))
}

/// Builds deterministic CBOR (WIRE §5.1) from JSON text.
///
/// Objects become maps (duplicate keys are refused), arrays arrays, strings text (which
/// must be NFC), `true`/`false` booleans and integers integers. A number written with a
/// fraction or exponent becomes a decimal keeping every written digit (`1.50` is 150 × 10⁻²,
/// `1.5e3` is 15 × 10²), never a float. `null`, `NaN` and infinities are refused.
#[pyfunction]
fn canonical_cbor_from_json<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyBytes>> {
    let json = py.import("json")?;
    let decimal = py.import("decimal")?.getattr("Decimal")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("parse_float", &decimal)?;
    kwargs.set_item("parse_constant", wrap_pyfunction!(refuse_constant, py)?)?;
    kwargs.set_item("object_pairs_hook", wrap_pyfunction!(pairs_to_dict, py)?)?;
    let parsed = json.call_method("loads", (text,), Some(&kwargs))?;
    let value = to_value(&parsed, &decimal, 0)?;
    let bytes = cbor::encode(&value).map_err(wire_err)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn refuse_constant(name: &str) -> PyResult<()> {
    Err(json_err(format!("{name} is not a number the data model can hold")))
}

#[pyfunction]
fn pairs_to_dict<'py>(py: Python<'py>, pairs: Vec<(Bound<'py, PyString>, Bound<'py, PyAny>)>) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (k, v) in pairs {
        if dict.contains(&k)? {
            return Err(WireError::new_err(("E_CBOR_DUPLICATE", 0usize, format!("E_CBOR_DUPLICATE: duplicate key {k}"))));
        }
        dict.set_item(k, v)?;
    }
    Ok(dict)
}

fn to_value(obj: &Bound<'_, PyAny>, decimal: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    if depth > cbor::MAX_DEPTH {
        return Err(WireError::new_err(("E_SIZE", 0usize, "E_SIZE: nesting deeper than 16".to_owned())));
    }
    if obj.is_none() {
        return Err(json_err("null is not part of the data model"));
    }
    if let Ok(b) = obj.cast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if obj.is_instance_of::<PyInt>() {
        let i: i128 = obj.extract().map_err(|_| json_err("integer outside -2^64..2^64-1"))?;
        return Ok(Value::Int(i));
    }
    if let Ok(s) = obj.cast::<PyString>() {
        return Ok(Value::Text(s.to_str()?.to_owned()));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        return list.iter().map(|v| to_value(&v, decimal, depth + 1)).collect::<PyResult<_>>().map(Value::Array);
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = BTreeMap::new();
        for (k, v) in dict.iter() {
            map.insert(k.extract::<String>()?, to_value(&v, decimal, depth + 1)?);
        }
        return Ok(Value::Map(map));
    }
    if obj.is_instance(decimal)? {
        return decimal_value(obj);
    }
    Err(json_err(format!("unsupported JSON value {obj}")))
}

/// A `decimal.Decimal` read exactly from its `(sign, digits, exponent)` tuple.
fn decimal_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    let tuple = obj.call_method0("as_tuple")?;
    let tuple = tuple.cast::<PyTuple>()?;
    let sign: u8 = tuple.get_item(0)?.extract()?;
    let digits: Vec<u8> = tuple.get_item(1)?.extract()?;
    let exponent: i32 = tuple.get_item(2)?.extract().map_err(|_| json_err("not a finite decimal"))?;
    let mut mantissa: i128 = 0;
    for d in digits {
        mantissa = mantissa
            .checked_mul(10)
            .and_then(|m| m.checked_add(i128::from(d)))
            .ok_or_else(|| json_err("decimal mantissa too large"))?;
    }
    Ok(Value::Decimal(Decimal { mantissa: if sign == 1 { -mantissa } else { mantissa }, exponent }))
}

#[pymodule]
fn fieldseal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("WireError", m.py().get_type::<WireError>())?;
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(content_address, m)?)?;
    m.add_function(wrap_pyfunction!(key_id, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_cbor_from_json, m)?)?;
    Ok(())
}
