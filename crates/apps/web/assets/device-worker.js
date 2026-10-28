// The browser device's worker: hosts the WebAssembly core (the same Rust the other platforms run),
// persists its objects in IndexedDB and makes the blocking HTTP calls the contexts' synchronous
// ports need. The page talks to it by messages: {id, method, args} -> {id, ok, result | error}.
//
// Honest limits: the keys are software keys (unattested). At rest the "keys" namespace is wrapped
// with a non-extractable WebCrypto key kept in IndexedDB, which stops casual copying of the
// database but not a script running in this origin.
import init, { Device } from "/assets/wasm/fieldseal_wasm.js";

let device = null;
let db = null;
let wrapKey = null;

function req(r) {
  return new Promise((ok, fail) => { r.onsuccess = () => ok(r.result); r.onerror = () => fail(r.error); });
}

async function openDb() {
  const open = indexedDB.open("fieldseal-web-device", 1);
  open.onupgradeneeded = () => {
    open.result.createObjectStore("objects");
    open.result.createObjectStore("meta");
  };
  return req(open);
}

async function meta(key, value) {
  const store = db.transaction("meta", value === undefined ? "readonly" : "readwrite").objectStore("meta");
  return value === undefined ? req(store.get(key)) : req(store.put(value, key));
}

async function loadWrapKey() {
  let k = await meta("wrapKey");
  if (!k) {
    k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await meta("wrapKey", k);
  }
  wrapKey = k;
}

async function seal(bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return out;
}

async function unseal(bytes) {
  const iv = bytes.slice(0, 12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrapKey, bytes.slice(12)));
}

async function loadObjects() {
  const tx = db.transaction("objects", "readonly").objectStore("objects");
  const keys = await req(tx.getAllKeys());
  const out = [];
  for (const k of keys) {
    const v = await req(db.transaction("objects", "readonly").objectStore("objects").get(k));
    const bytes = v.ns === "keys" ? await unseal(v.bytes) : v.bytes;
    out.push([v.ns, v.name, bytes]);
  }
  return out;
}

async function persist(changes) {
  if (!changes.length) return;
  const prepared = [];
  for (const [ns, name, bytes] of changes) {
    prepared.push([ns, name, bytes === null ? null : ns === "keys" ? await seal(bytes) : bytes]);
  }
  const tx = db.transaction("objects", "readwrite");
  const store = tx.objectStore("objects");
  for (const [ns, name, bytes] of prepared) {
    if (bytes === null) store.delete(`${ns}/${name}`);
    else store.put({ ns, name, bytes }, `${ns}/${name}`);
  }
  await new Promise((ok, fail) => { tx.oncomplete = ok; tx.onerror = () => fail(tx.error); tx.onabort = () => fail(tx.error); });
}

// One blocking POST for the upload transport (allowed in a worker).
// The device addresses the upload endpoint by its real URL (the proof-of-possession token is
// bound to it, DEL-062); this page reaches it through its own same-origin proxy.
let upstream = null;
globalThis.fieldsealPost = (url, pop, body) => {
  if (upstream && url.startsWith(upstream)) url = "/proxy/upload" + url.slice(upstream.length);
  const x = new XMLHttpRequest();
  x.open("POST", url, false);
  x.responseType = "arraybuffer";
  x.setRequestHeader("Content-Type", "application/cbor");
  if (pop) x.setRequestHeader("Fieldseal-PoP", pop);
  x.send(body);
  return { status: x.status, body: new Uint8Array(x.response || new ArrayBuffer(0)) };
};

async function start(provisioning) {
  await init();
  upstream = (JSON.parse(provisioning).uploadUrl || "").replace(/\/$/, "") || null;
  db = await openDb();
  await loadWrapKey();
  const boots = ((await meta("boots")) || 0) + 1;
  await meta("boots", boots);
  device = new Device(provisioning, await loadObjects(), boots);
  return { boots };
}

async function call(method, args) {
  if (method === "start") return start(...args);
  if (method === "forget") {
    // Erase this device's objects from the browser (the wrap key and boot count stay).
    const changes = device ? Array.from(device.eraseAll()) : [];
    await persist(changes);
    device = null;
    return null;
  }
  if (!device) throw new Error("the device is not started");
  let r = device[method](...args);
  if (r && typeof r === "object" && "words" in r && "tenancy" in r) r = { file: r.file, words: r.words, tenancy: r.tenancy };
  await persist(Array.from(device.drainChanges()));
  const downloads = Array.from(device.takeDownloads());
  return { r, downloads };
}

self.onmessage = async (e) => {
  const { id, method, args } = e.data;
  try {
    const result = await call(method, args || []);
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: typeof err === "string" ? err : (err && err.message) || String(err) });
  }
};
