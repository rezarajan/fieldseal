//! The browser device as a WebAssembly object (the `web` platform profile, ADR 0036).
//!
//! A thin shell over [`fieldseal_adapters_web::device::WebDevice`]. The host page runs it in a
//! dedicated worker, because uploads use a blocking HTTP call (`fieldsealPost`, defined by the
//! worker script) and the contexts' ports are synchronous. Persistence is the host's job:
//! after every call it drains [`Device::drain_changes`] into IndexedDB.

use std::rc::Rc;

use fieldseal_adapters_web::device::{Host, WebDevice};
use fieldseal_adapters_web::platform::Namespace;
use fieldseal_adapters_web::workbench::{RenderOptions, parse_map};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// Defined by the worker script: one blocking POST. Returns `{status, body: Uint8Array}`.
    #[wasm_bindgen(js_name = fieldsealPost, catch)]
    fn fieldseal_post(url: &str, pop: Option<String>, body: &[u8]) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn performance_now() -> f64;
}

fn js(e: impl ToString) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn host() -> Host {
    Host {
        now_ms: Rc::new(js_sys::Date::now),
        elapsed_ms: Rc::new(performance_now),
        post: Rc::new(|url, pop, body| {
            let r = fieldseal_post(url, pop.map(str::to_owned), body).map_err(|e| e.as_string().unwrap_or_else(|| "request failed".into()))?;
            let status = js_sys::Reflect::get(&r, &"status".into()).ok().and_then(|v| v.as_f64()).ok_or("no status")? as u16;
            let body = js_sys::Reflect::get(&r, &"body".into()).map_err(|_| "no body")?;
            Ok((status, Uint8Array::new(&body).to_vec()))
        }),
    }
}

fn options(json: &str) -> Result<RenderOptions, JsValue> {
    let map = if json.trim().is_empty() { Default::default() } else { parse_map(json).map_err(js)? };
    let mut o = RenderOptions::default();
    if let Some(fieldseal_kernel::Value::Int(i)) = map.get("layout") {
        o.layout = Some(*i as usize);
    }
    if let Some(fieldseal_kernel::Value::Array(a)) = map.get("languages") {
        o.languages = a.iter().filter_map(|v| v.as_text().map(str::to_owned)).collect();
    }
    if let Some(w) = map.get("window").and_then(|v| v.as_text()) {
        o.window = Some(fieldseal_instrument::domain::WindowClass::from_name(w).ok_or_else(|| js("bad window class"))?);
    }
    Ok(o)
}

/// The registration request built from a token.
#[wasm_bindgen]
pub struct RegistrationRequest {
    file: Vec<u8>,
    words: String,
    tenancy: String,
}

#[wasm_bindgen]
impl RegistrationRequest {
    /// The request file to POST to the factory.
    #[wasm_bindgen(getter)]
    pub fn file(&self) -> Vec<u8> {
        self.file.clone()
    }
    /// The four words to compare with the portal.
    #[wasm_bindgen(getter)]
    pub fn words(&self) -> String {
        self.words.clone()
    }
    /// The tenancy (hex), used to poll the status.
    #[wasm_bindgen(getter)]
    pub fn tenancy(&self) -> String {
        self.tenancy.clone()
    }
}

/// A device in the browser.
#[wasm_bindgen]
pub struct Device {
    inner: WebDevice,
}

#[wasm_bindgen]
impl Device {
    /// Opens the device from the authority's provisioning JSON and the persisted objects, an
    /// array of `[namespace, name, Uint8Array]`. `boot_count` counts page loads.
    #[wasm_bindgen(constructor)]
    pub fn new(provisioning: &str, persisted: Array, boot_count: u32) -> Result<Device, JsValue> {
        let mut objects = Vec::new();
        for item in persisted.iter() {
            let t = Array::from(&item);
            let ns = t.get(0).as_string().and_then(|s| Namespace::parse(&s)).ok_or_else(|| js("bad namespace"))?;
            let name = t.get(1).as_string().ok_or_else(|| js("bad name"))?;
            objects.push((ns, name, Uint8Array::new(&t.get(2)).to_vec()));
        }
        Ok(Device { inner: WebDevice::open(provisioning, objects, boot_count, host()).map_err(js)? })
    }

    /// Changes to persist: an array of `[namespace, name, Uint8Array | null]`.
    #[wasm_bindgen(js_name = drainChanges)]
    pub fn drain_changes(&self) -> Array {
        let out = Array::new();
        for c in self.inner.drain_changes() {
            let t = Array::new();
            t.push(&c.namespace.name().into());
            t.push(&c.name.into());
            t.push(&c.bytes.map_or(JsValue::NULL, |b| Uint8Array::from(&b[..]).into()));
            out.push(&t);
        }
        out
    }

    /// Everything to delete from the host's store to erase the device.
    #[wasm_bindgen(js_name = eraseAll)]
    pub fn erase_all(&self) -> Array {
        let out = Array::new();
        for c in self.inner.erase_all() {
            let t = Array::new();
            t.push(&c.namespace.name().into());
            t.push(&c.name.into());
            t.push(&JsValue::NULL);
            out.push(&t);
        }
        out
    }

    /// Files offered for download since the last call: `[name, Uint8Array]` pairs.
    #[wasm_bindgen(js_name = takeDownloads)]
    pub fn take_downloads(&self) -> Array {
        let out = Array::new();
        for (name, bytes) in self.inner.take_downloads() {
            let t = Array::new();
            t.push(&name.into());
            t.push(&Uint8Array::from(&bytes[..]).into());
            out.push(&t);
        }
        out
    }

    /// The device state as JSON.
    pub fn state(&mut self) -> String {
        self.inner.state_json()
    }

    /// Creates the tenancy protected by a PIN of at least six digits.
    #[wasm_bindgen(js_name = createTenancy)]
    pub fn create_tenancy(&mut self, pin: &str) -> Result<String, JsValue> {
        self.inner.create_tenancy(pin).map_err(js)
    }

    /// Opens a session with the PIN.
    pub fn unlock(&mut self, pin: &str) -> Result<String, JsValue> {
        self.inner.unlock(pin).map_err(js)
    }

    /// Locks the session.
    pub fn lock(&mut self) {
        self.inner.lock();
    }

    /// The public keys, hex, for `fieldseal bundle build`.
    #[wasm_bindgen(js_name = publicKeys)]
    pub fn public_keys(&self) -> String {
        self.inner.public_keys_json()
    }

    /// Builds the sealed registration request from a token.
    #[wasm_bindgen(js_name = registrationRequest)]
    pub fn registration_request(&mut self, token: &str, label: &str) -> Result<RegistrationRequest, JsValue> {
        let r = self.inner.registration_request(token, label).map_err(js)?;
        Ok(RegistrationRequest { file: r.file, words: r.words, tenancy: r.tenancy })
    }

    /// Verifies and imports a bundle; the JSON report lists each security step.
    #[wasm_bindgen(js_name = importBundle)]
    pub fn import_bundle(&mut self, file: &[u8]) -> Result<String, JsValue> {
        self.inner.import_bundle(file).map_err(js)
    }

    /// The held instrument, subjects and consent bases as JSON.
    pub fn held(&self) -> Result<String, JsValue> {
        self.inner.held_json().map_err(js)
    }

    /// Draws the held instrument (same render as `instrument preview`).
    pub fn render(&mut self, options_json: &str, values: &str, roster: &str) -> Result<String, JsValue> {
        let v = if values.trim().is_empty() { None } else { Some(parse_map(values).map_err(js)?) };
        let r = if roster.trim().is_empty() { None } else { Some(parse_map(roster).map_err(js)?) };
        self.inner.render(&options(options_json)?, v.as_ref(), r.as_ref()).map_err(js)
    }

    /// Evaluates the held instrument's rules live.
    pub fn evaluate(&mut self, options_json: &str, values: &str, roster: &str) -> Result<String, JsValue> {
        let v = if values.trim().is_empty() { Default::default() } else { parse_map(values).map_err(js)? };
        let r = if roster.trim().is_empty() { Default::default() } else { parse_map(roster).map_err(js)? };
        self.inner.evaluate(&options(options_json)?, &v, &r).map_err(js)
    }

    /// The roster fields of a subject, as JSON.
    #[wasm_bindgen(js_name = rosterFields)]
    pub fn roster_fields(&self, subject: &str) -> Result<String, JsValue> {
        let m = self.inner.roster_fields(subject).map_err(js)?;
        Ok(fieldseal_adapters_web::workbench::map_json(&m))
    }

    /// Records consent.
    #[wasm_bindgen(js_name = recordConsent)]
    pub fn record_consent(&mut self, subject: &str, basis: &str, statement_version: u32) -> Result<String, JsValue> {
        self.inner.record_consent(subject, basis, statement_version).map_err(js)
    }

    /// Records absent, declines or not-them.
    #[wasm_bindgen(js_name = recordStatus)]
    pub fn record_status(&mut self, subject: &str, outcome: &str) -> Result<String, JsValue> {
        self.inner.record_status(subject, outcome).map_err(js)
    }

    /// Starts a capture; throws `consent_needed` when consent comes first.
    #[wasm_bindgen(js_name = startCapture)]
    pub fn start_capture(&mut self, subject: &str, mode: &str) -> Result<String, JsValue> {
        self.inner.start_capture(subject, mode).map_err(js)
    }

    /// Sets answers (JSON object of path to value) and returns the core's verdicts.
    #[wasm_bindgen(js_name = setValues)]
    pub fn set_values(&mut self, values: &str) -> Result<String, JsValue> {
        self.inner.set_values(values).map_err(js)
    }

    /// Keeps a soft verdict with a reason.
    #[wasm_bindgen(js_name = overrideSoft)]
    pub fn override_soft(&mut self, rule: &str, reason: &str) -> Result<(), JsValue> {
        self.inner.override_soft(rule, reason).map_err(js)
    }

    /// Acknowledges unanswered items.
    #[wasm_bindgen(js_name = acknowledgeIncomplete)]
    pub fn acknowledge_incomplete(&mut self, count: usize) -> Result<(), JsValue> {
        self.inner.acknowledge_incomplete(count).map_err(js)
    }

    /// Seals the capture.
    pub fn seal(&mut self) -> Result<String, JsValue> {
        self.inner.seal().map_err(js)
    }

    /// Discards the capture.
    #[wasm_bindgen(js_name = discardCapture)]
    pub fn discard_capture(&mut self) {
        self.inner.discard_capture();
    }

    /// The review as JSON.
    pub fn review(&mut self) -> Result<String, JsValue> {
        self.inner.review().map_err(js)
    }

    /// Builds, verifies and offers the export for download.
    pub fn export(&mut self, parity: bool) -> Result<String, JsValue> {
        self.inner.export(parity).map_err(js)
    }

    /// Uploads to the endpoint at `address`.
    pub fn upload(&mut self, address: &str) -> Result<String, JsValue> {
        self.inner.upload(address).map_err(js)
    }

    /// Verifies and applies a receipt file.
    #[wasm_bindgen(js_name = importReceipt)]
    pub fn import_receipt(&mut self, bytes: &[u8]) -> Result<String, JsValue> {
        self.inner.import_receipt(bytes).map_err(js)
    }

    /// What a clear would do.
    #[wasm_bindgen(js_name = clearPreview)]
    pub fn clear_preview(&mut self, through: f64) -> Result<String, JsValue> {
        self.inner.clear_preview(through as u64).map_err(js)
    }

    /// Clears through `through`, the PIN entered twice.
    pub fn clear(&mut self, through: f64, first: &str, second: &str) -> Result<String, JsValue> {
        self.inner.clear(through as u64, first, second).map_err(js)
    }

    /// The highest sealed `seq`.
    #[wasm_bindgen(js_name = lastSeq)]
    pub fn last_seq(&self) -> Result<f64, JsValue> {
        self.inner.last_seq().map(|n| n as f64).map_err(js)
    }
}
