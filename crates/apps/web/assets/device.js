// The Device page. The device itself (the Rust core compiled to WebAssembly) runs in a worker;
// this script is the plain user interface around it: one step at a time (Session, Capture,
// Review and seal, Export), one screen of it, one primary action on each. Every security result
// shown here is reported by the core, not decided here.
import { readAnswerEntries, readAnswers, applyVisibility } from "/assets/answers.js";

const $ = (id) => document.getElementById(id);
const root = $("device");
const worker = new Worker("/assets/device-worker.js", { type: "module" });
const waiting = new Map();
let counter = 0;

let device = { tenancy: null, unlocked: false, bundle: null };
let started = false;
let startError = null;
let held = null;
let registered = false;
let regChecked = null; // the tenancy whose registration state was read
let capture = null; // { subject, name, options, window, roster, sent: Map, view, problems: Map, ev }
let phase = "session"; // session | about | review | export
let reviewScreen = "review";
let exportScreen = "ready";
let consentSubject = null;
let lastExportName = null;
let uploadUrl = null;
let aboutLabel = "Capture";
let ackChecked = false;
let pickedInstrument = null;
let summary = { sealed: new Set(), records: 0, undelivered: 0 };

const PHASES = ["session", "about", "review", "export"];

worker.onmessage = (e) => {
  const { id, ok, result, error } = e.data;
  const p = waiting.get(id);
  waiting.delete(id);
  if (!p) return;
  if (ok) p.ok(result); else p.fail(new Error(error));
};

function call(method, ...args) {
  return new Promise((ok, fail) => {
    const id = ++counter;
    waiting.set(id, { ok, fail });
    worker.postMessage({ id, method, args });
  }).then((res) => {
    if (res && res.downloads) for (const [name, bytes] of res.downloads) offerDownload(name, bytes);
    return res && "r" in res ? res.r : res;
  });
}

function offerDownload(name, bytes) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = (lastExportName || "export") + ".fieldseal";
  a.textContent = "Download " + a.download + " (" + bytes.length + " bytes)";
  a.className = "link";
  $("export-out").append(document.createElement("br"), a);
}

// ---- the log, the latest result ------------------------------------------------------------

let logCount = 0;
function setLatest(text, bad) {
  const line = $("latest");
  line.textContent = text.length > 220 ? text.slice(0, 217) + "..." : text;
  line.classList.toggle("bad", !!bad);
}

// `brief` is the short line shown beside the primary action; the full text goes to the log.
function log(ok, text, brief) {
  const li = document.createElement("li");
  li.className = ok ? "ok" : "fail";
  li.textContent = (ok ? "ok: " : "FAILED: ") + text;
  $("log").append(li);
  $("log-count").textContent = String(++logCount);
  setLatest(brief || text, !ok);
  return li;
}

function fail(where, e) {
  const m = String(e && e.message ? e.message : e);
  log(false, where + ": " + m);
  return m;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function kv(box, rows) {
  box.replaceChildren();
  const dl = document.createElement("dl");
  for (const [k, v] of rows) dl.append(el("dt", "", k), el("dd", "", v));
  box.append(dl);
}

// ---- which screen ---------------------------------------------------------------------------

// Set by "Load another survey": the session shows the survey chooser again.
let choosingSurvey = false;
// Set when the factory does not know this device's tenancy (it was reset): register again.
let factoryForgot = false;
function forgotten() {
  factoryForgot = true;
  registered = false;
  try { localStorage.removeItem("fs-registered-" + device.tenancy); } catch { /* private window */ }
  const note = document.getElementById("factory-forgot");
  if (note) note.hidden = false;
}

function ready() { return !!(device.unlocked && device.bundle); }

function sessionScreen() {
  if (startError) return "unavailable";
  if (!started) return "starting";
  if (!device.tenancy) return "create";
  if (!device.unlocked) return "unlock";
  if (factoryForgot) return "register";
  if (!device.bundle) return registered ? "bundle" : "register";
  if (choosingSurvey) return "bundle";
  if (consentSubject) return "consent";
  return "roster";
}

function paint() {
  let step = phase;
  let screen;
  if (!started || !ready()) { step = "session"; phase = "session"; screen = sessionScreen(); }
  else if (phase === "session") screen = sessionScreen();
  else if (phase === "about") screen = "capture";
  else if (phase === "review") screen = reviewScreen;
  else screen = exportScreen;

  for (const section of root.querySelectorAll("section[data-step]")) {
    const on = section.dataset.step === step;
    section.hidden = !on;
    if (on) for (const s of section.querySelectorAll("[data-screen]")) s.hidden = s.dataset.screen !== screen;
  }
  root.dataset.step = step;
  root.dataset.screen = screen;
  const at = PHASES.indexOf(step);
  for (const li of root.querySelectorAll("#pills li")) {
    const i = PHASES.indexOf(li.dataset.pill);
    if (i === at) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
    li.classList.toggle("done", i < at);
    if (li.dataset.pill === "about") li.textContent = step === "about" ? aboutLabel : "Capture";
  }
  $("lock").hidden = !(started && device.unlocked);
  if (step === "session" && screen === "create") pins.create.focus();
  if (step === "session" && screen === "unlock") pins.unlock.focus();
}

// ---- state ----------------------------------------------------------------------------------

async function factoryState() {
  if (!device.tenancy) return null;
  try {
    const r = await fetch("/proxy/factory/v1/registrations/" + device.tenancy);
    // The factory's answer wins: a tenancy it does not know is not registered (a reset factory).
    if (r.status === 404) return "unknown";
    if (!r.ok) return null;
    return (await r.json()).state || null;
  } catch { return null; }
}

async function refresh() {
  device = JSON.parse(await call("state"));
  kv($("device-info"), [
    ["Authority", device.authority || "(none)"],
    ["Keys", device.unattested ? "software keys, unattested (not in hardware)" : "?"],
    ["Tenancy", device.tenancy ? device.tenancy.slice(0, 16) + "... (" + device.state + ")" : "none yet"],
    ["Session", device.unlocked ? "unlocked" : "locked"],
    ["Bundle", device.bundle ? (device.bundle.practice ? "held (practice: no rosters)" : `held: ${device.bundle.rosters} roster(s), ${device.bundle.subjects} subject(s), ${device.bundle.layouts} layout(s)`) : "none"],
    ["Key count", String(device.keys)],
  ]);
  $("posture").textContent = device.posture.length ? `${device.posture.length} restriction(s) not in force or unreadable: a browser cannot lock a device down (PLAT-043; findings never block).` : "";
  $("tenancy-info").textContent = device.tenancy ? "Tenancy " + device.tenancy : "";

  if (device.tenancy && device.unlocked && (!device.bundle || choosingSurvey)) {
    if (!root.dataset.factory) registered = true;
    else if (regChecked !== device.tenancy) {
      regChecked = device.tenancy;
      const st = await factoryState();
      // Only an unreachable factory falls back to what this browser remembers.
      registered = st === "registered" || (st === null && storedFlag("fs-registered-" + device.tenancy));
      if (st === "unknown") forgotten();
      if (st === "pending") watchRegistration("A request is waiting for confirmation at the factory.");
    }
  }
  if (!device.bundle) held = null;
  if (ready() && !held) held = JSON.parse(await call("held"));
  if (ready() && phase === "session" && !capture) await renderRoster();
  paint();
}

function storedFlag(key) {
  try { return localStorage.getItem(key) === "1"; } catch { return false; }
}

// ---- PIN pads -------------------------------------------------------------------------------

function initPin(box) {
  const input = box.querySelector(".pin-input");
  const dots = box.querySelector(".dots");
  const pad = box.querySelector(".pad");
  const draw = () => {
    const n = input.value.length;
    dots.replaceChildren();
    for (let i = 0; i < Math.max(6, n); i++) dots.append(el("span", i < n ? "on" : ""));
    dots.setAttribute("aria-label", n + " digits entered");
  };
  const changed = () => input.dispatchEvent(new Event("input"));
  for (const k of ["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "del"]) {
    const b = document.createElement("button");
    b.type = "button";
    if (k === "") { b.className = "spacer"; b.disabled = true; b.tabIndex = -1; b.setAttribute("aria-hidden", "true"); }
    else if (k === "del") {
      b.className = "del"; b.textContent = "Delete"; b.setAttribute("aria-label", "Delete the last digit");
      b.addEventListener("click", () => { input.value = input.value.slice(0, -1); changed(); });
    } else {
      b.textContent = k;
      b.addEventListener("click", () => { input.value += k; changed(); });
    }
    pad.append(b);
  }
  input.addEventListener("input", () => { input.value = input.value.replace(/\D/g, "").slice(0, 16); draw(); });
  // The keyboard works too: digits type, Backspace deletes, Enter submits; whenever this pad is
  // on screen and no other text field has the focus.
  document.addEventListener("keydown", (e) => {
    if (!box.offsetParent || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    // Typing into the PIN field itself is the browser's own input; any other text field keeps its keys.
    if (t === input || (t.matches && t.matches("input:not([type=radio]):not([type=checkbox]), textarea, select"))) return;
    if (/^[0-9]$/.test(e.key)) { e.preventDefault(); input.value = (input.value + e.key).slice(0, 16); changed(); }
    else if (e.key === "Backspace") { e.preventDefault(); input.value = input.value.slice(0, -1); changed(); }
    else if (e.key === "Enter") { const f = box.closest("form"); if (f) { e.preventDefault(); f.requestSubmit(); } }
  });
  draw();
  return { reset() { input.value = ""; draw(); }, focus() { input.focus({ preventScroll: true }); } };
}

const pins = {
  create: initPin($("form-create").querySelector("[data-pin]")),
  unlock: initPin($("form-unlock").querySelector("[data-pin]")),
};

// ---- tenancy --------------------------------------------------------------------------------

let firstPin = null;
function resetCreate() {
  firstPin = null;
  pins.create.reset();
  $("create-title").textContent = "Create your PIN";
  $("create-hint").textContent = "Six or more digits. It protects everything this device keeps.";
  $("create-go").textContent = "Continue";
}

$("form-create").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("create-error");
  err.textContent = "";
  const v = $("pin-new").value;
  if (v.length < 6) { err.textContent = "Use six or more digits."; return; }
  if (firstPin === null) {
    firstPin = v;
    pins.create.reset();
    $("create-title").textContent = "Enter it again";
    $("create-hint").textContent = "The same PIN once more, so a mistyped digit cannot lock you out.";
    $("create-go").textContent = "Create PIN";
    return;
  }
  if (v !== firstPin) { resetCreate(); err.textContent = "The two entries did not match. Start again."; return; }
  $("create-go").disabled = true;
  try {
    await call("createTenancy", v);
    resetCreate();
    log(true, "tenancy created; the PIN was hashed with Argon2id and wrapped keys were generated in the core (COL-001, COL-020)", "PIN set; keys generated on this device");
    await refresh();
  } catch (x) { err.textContent = fail("create tenancy", x); }
  $("create-go").disabled = false;
});

$("form-unlock").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("unlock-error");
  err.textContent = "";
  $("unlock-go").disabled = true;
  try {
    await call("unlock", $("pin").value);
    pins.unlock.reset();
    log(true, "session opened with the PIN; the held bundle was re-verified (COL-022)", "unlocked; the held bundle was verified again");
    await refresh();
  } catch (x) { pins.unlock.reset(); err.textContent = fail("unlock", x); }
  $("unlock-go").disabled = false;
});

$("lock").addEventListener("click", async () => {
  if (capture) { await call("discardCapture"); capture = null; }
  await call("lock");
  log(true, "session locked", "locked");
  phase = "session";
  await refresh();
});

// ---- registration ---------------------------------------------------------------------------

let poller = null;
function watchRegistration(text) {
  let status = $("reg-status");
  if (!status) {
    status = el("p", "lead");
    status.id = "reg-status";
    $("register-result").append(status);
  }
  status.textContent = text;
  const poll = async () => {
    const st = await factoryState();
    if (st) status.textContent = "Status: " + st;
    if (st === "registered") {
      clearInterval(poller);
      try { localStorage.setItem("fs-registered-" + device.tenancy, "1"); } catch { /* private window */ }
      factoryForgot = false;
      const note = document.getElementById("factory-forgot");
      if (note) note.hidden = true;
      registered = true;
      log(true, "registration confirmed by the collector at the factory: tenancy registered", "registered; the factory confirmed this device");
      await refresh();
    }
  };
  clearInterval(poller);
  poller = setInterval(() => poll().catch(() => {}), 2000);
}

$("form-register").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("register-result");
  out.replaceChildren();
  $("register-go").disabled = true;
  try {
    const r = await call("registrationRequest", $("token").value, $("label").value);
    log(true, "registration request built and sealed in this browser from the device's own keys; four words: " + r.words, "request sent; compare the four words with the portal");
    const res = await fetch("/proxy/factory/v1/registrations", { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: r.file });
    const text = await res.text();
    log(res.ok, "the factory answered " + res.status + " " + text, res.ok ? "request sent; compare the four words with the portal" : "the factory refused the request");
    if (!res.ok) { out.append(el("p", "msg bad", "The factory answered " + res.status + ": " + text)); $("register-go").disabled = false; return; }
    out.append(el("p", "lead", "Compare these four words with the ones the portal shows for this request, and confirm there only if all four match."), el("div", "words", r.words));
    watchRegistration("Waiting for confirmation at the factory.");
    const st = await factoryState();
    if (st) $("reg-status").textContent = "Status: " + st;
  } catch (x) {
    out.append(el("p", "msg bad", fail("registration", x)));
    $("register-go").disabled = false;
  }
});

// ---- bundle ---------------------------------------------------------------------------------

function showBundle(report) {
  const ol = $("bundle-steps");
  ol.replaceChildren();
  for (const s of report.steps) {
    ol.append(el("li", s.ok ? "ok" : "fail", (s.ok ? "ok: " : "FAILED: ") + s.step + ": " + s.detail));
    log(s.ok, "bundle " + s.step + ": " + s.detail, `bundle ${s.step}: ${s.detail}`);
  }
}

async function importBundle(bytes) {
  $("bundle-error").textContent = "";
  try {
    const report = JSON.parse(await call("importBundle", bytes));
    showBundle(report);
    const n = report.publications.length;
    const first = report.publications[0];
    log(true, `bundle verified: ${first ? first.signatures + "-of-" + first.threshold + " publisher signatures" : "no publications"}, ${n} publication(s), log inclusion ok`);
    registered = true;
    choosingSurvey = false;
    await refresh();
  } catch (x) {
    $("bundle-steps").replaceChildren(el("li", "fail", "FAILED: " + fail("bundle", x)));
    $("bundle-error").textContent = "The bundle was not accepted: " + (x && x.message ? x.message : x);
  }
}

function setupBundleScreen() {
  // The stack (and the standalone demo authority) build bundles on request.
  const demo = root.dataset.mode === "demo" || root.dataset.mode === "stack";
  $("fetch-bundle").hidden = !demo;
  if (!demo) {
    const open = $("open-bundle");
    open.className = "btn btn-primary";
    open.textContent = "Open a bundle file";
  }
  const names = (root.dataset.instruments || "").split(",").filter(Boolean);
  // Every published survey is a choice; none is preselected (the demo shows a device carrying
  // any of them). Loading is possible once one is chosen.
  pickedInstrument = null;
  const box = $("instrument-pick");
  const fetchButton = $("fetch-bundle");
  if (demo && names.length) {
    box.replaceChildren(box.querySelector("legend") || el("legend"));
    const title = (n) => n.replace(/[-_]+/g, " ").replace(/^./, (c) => c.toUpperCase());
    for (const n of names) {
      const label = el("label", "survey-choice");
      const input = document.createElement("input");
      input.type = "radio"; input.name = "instrument"; input.value = n;
      input.addEventListener("change", () => { pickedInstrument = n; fetchButton.disabled = false; fetchButton.textContent = "Load: " + title(n); });
      const name = el("span", "survey-name"); name.textContent = title(n);
      const id = el("code", "survey-id"); id.textContent = n;
      label.append(input, name, id);
      box.append(label);
    }
    box.hidden = false;
    fetchButton.disabled = true;
  } else if (demo) {
    $("bundle-error").textContent = "No survey is published yet. Publish one through the stack's log first: just publish";
  }
}

$("fetch-bundle").addEventListener("click", async () => {
  $("bundle-error").textContent = "";
  const res = await fetch(`/device/bundle?tenancy=${device.tenancy}${pickedInstrument ? "&instrument=" + encodeURIComponent(pickedInstrument) : ""}`);
  if (!res.ok) {
    const why = await res.text();
    if (/no such tenancy|not registered|unknown tenancy/i.test(why)) { forgotten(); paint(); return; }
    $("bundle-error").textContent = fail("fetch bundle", why);
    return;
  }
  if (res.headers.get("X-Bundle-Development-Allowance") === "true") log(true, "note: the device is unattested software; the development policy allows releasing rosters to it (REG-017). Production policy never does.");
  await importBundle(new Uint8Array(await res.arrayBuffer()));
});

$("bundle-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (f) await importBundle(new Uint8Array(await f.arrayBuffer()));
  e.target.value = "";
});

$("keys-link").addEventListener("click", async () => {
  $("keys-out").textContent = await call("publicKeys");
  $("keys-out").hidden = false;
});

$("retry").addEventListener("click", () => location.reload());

// ---- the session: the roster ----------------------------------------------------------------

function subjectName(s) {
  return Object.values(s.display)[0] || s.subject;
}

async function loadSummary() {
  try {
    const r = JSON.parse(await call("review"));
    const sealed = new Set();
    let records = 0, undelivered = 0;
    for (const s of r.subjects) {
      if (s.records.length) sealed.add(s.subject);
      for (const x of s.records) { records++; if (!/^(delivered|received|cleared)/i.test(x.delivery)) undelivered++; }
    }
    summary = { sealed, records, undelivered };
  } catch (x) { fail("review", x); }
}

async function renderRoster() {
  if (!held) return;
  await loadSummary();
  const box = $("subjects");
  box.replaceChildren();
  let total = 0;
  let next = null;
  let nextRow = null;
  for (const r of held.rosters) {
    box.append(el("div", "cohort", `${r.cohort} (version ${r.version})`));
    for (const s of r.subjects) {
      total++;
      const sealed = summary.sealed.has(s.subject);
      const name = subjectName(s);
      const b = el("button", "subject");
      b.type = "button";
      b.dataset.subject = s.subject;
      const who = el("span", "who");
      who.append(el("b", "", name), el("small", "", name === s.subject ? r.cohort : s.subject));
      b.append(el("span", "seat", name.trim().slice(0, 1).toUpperCase() || "?"), who);
      if (sealed) b.append(el("span", "tag sealed", "Sealed"));
      else if (held.consent.required) b.append(el("span", "tag " + (s.consent === "granted" ? "given" : s.consent === "refused" ? "refused" : ""), "Consent: " + s.consent));
      if (held.consent.required && s.consent === "refused") { b.disabled = true; }
      if (!b.disabled) b.append(el("span", "go", sealed ? "Resurvey" : "Start"));
      b.addEventListener("click", () => begin(s.subject, sealed ? "resurvey" : "first"));
      box.append(b);
      if (!next && !sealed && !b.disabled) { next = s; nextRow = b; }
    }
  }
  const start = $("start-next");
  if (next) {
    nextRow.classList.add("next");
    start.textContent = "Start " + subjectName(next);
    start.onclick = () => begin(next.subject, "first");
    start.hidden = false;
  } else {
    start.hidden = true;
  }
  const one = held.rosters.length === 1 ? held.rosters[0] : null;
  $("roster-title").textContent = one ? one.cohort : "Session";
  $("roster-sub").textContent = one ? `List version ${one.version}` : `${held.rosters.length} lists`;
  const done = summary.sealed.size;
  $("roster-count").textContent = total ? `${done} of ${total} sealed` : "Nobody is listed for this session.";
  $("roster-bar").style.width = total ? Math.round((100 * done) / total) + "%" : "0";
}

$("to-export").addEventListener("click", () => toExport());
$("another-survey").addEventListener("click", () => { choosingSurvey = true; paint(); });
$("sealed-export").addEventListener("click", () => toExport());

async function toRoster() {
  consentSubject = null;
  phase = "session";
  await refresh();
}

// ---- consent, then capture ------------------------------------------------------------------

async function begin(subject, mode = "first") {
  $("capture-error").textContent = "";
  try {
    const view = JSON.parse(await call("startCapture", subject, mode));
    consentSubject = null;
    await open(subject, view);
  } catch (err) {
    if (String(err.message).includes("consent_needed") && held.consent.required) {
      consentSubject = subject;
      $("consent-text").textContent = `Consent is required before capturing about ${subject} (COL-031). Record the basis on which it was given.`;
      const box = $("consent-basis");
      box.replaceChildren();
      for (const b of held.consent.bases) {
        const label = el("label");
        const input = document.createElement("input");
        input.type = "radio"; input.name = "basis"; input.value = b;
        label.append(input, document.createTextNode(b));
        box.append(label);
      }
      $("consent-error").textContent = "";
      paint();
    } else {
      $("capture-error").textContent = fail("start capture", err);
    }
  }
}

$("form-consent").addEventListener("submit", async (e) => {
  e.preventDefault();
  const basis = $("consent-basis").querySelector("input:checked");
  if (!basis) { $("consent-error").textContent = "Choose the basis on which consent was given."; return; }
  try {
    await call("recordConsent", consentSubject, basis.value, held.consent.statementVersion);
    log(true, "consent recorded and sealed for " + consentSubject, "consent recorded");
    await begin(consentSubject, "first");
  } catch (x) { $("consent-error").textContent = fail("consent", x); }
});

$("consent-back").addEventListener("click", () => { consentSubject = null; paint(); });

function windowClass() {
  const w = $("frame").clientWidth || innerWidth;
  return w < 600 ? "compact" : w < 840 ? "medium" : "expanded";
}

function optionsFor(cls) {
  return JSON.stringify({ languages: [navigator.language.split("-")[0]], window: cls });
}

// The shell carries the subject name and the step pills, so the form's own title block (a
// preview banner and the instrument's name) is left out of the frame; the title goes in the bar.
function wire(doc) {
  for (const type of ["input", "change", "click"]) doc.addEventListener(type, schedule);
  const top = doc.querySelector("header.top");
  if (top) {
    const h = top.querySelector("h1");
    if (h) $("capture-title").textContent = h.textContent.trim();
    top.style.display = "none";
  }
}

async function open(subject, view) {
  const roster = await call("rosterFields", subject);
  const s = held.rosters.flatMap((r) => r.subjects).find((x) => x.subject === subject);
  phase = "about";
  aboutLabel = "Capture";
  capture = { subject, name: s ? subjectName(s) : subject, window: null, options: null, roster, sent: new Map(), view, problems: new Map(), ev: null };
  $("capture-subject").textContent = capture.name;
  $("verdicts").replaceChildren();
  $("close-confirm").hidden = true;
  $("discard").hidden = false;
  $("to-review").disabled = false;
  paint();
  await new Promise((r) => requestAnimationFrame(r));
  capture.window = windowClass();
  capture.options = optionsFor(capture.window);
  const html = await call("render", capture.options, "", roster);
  const doc = $("frame").contentDocument;
  doc.open();
  doc.write(html);
  doc.close();
  wire(doc);
  log(true, `capture opened for ${subject}: the form is the core's render plan drawn by the HTML adapter, rules and field checks are evaluated by the core`, `capture opened for ${capture.name}`);
  await sync();
}

// Empties one question's controls; true when something was set.
function clearQuestion(q) {
  let did = false;
  for (const c of q.querySelectorAll("input, select, textarea")) {
    if (c.type === "radio" || c.type === "checkbox") { if (c.checked) { c.checked = false; did = true; } }
    else if (c.tagName !== "SELECT" && c.value !== "") { c.value = ""; c.removeAttribute("data-canonical"); did = true; }
  }
  for (const b of q.querySelectorAll(".nr-btn[aria-pressed=true]")) { b.setAttribute("aria-pressed", "false"); did = true; }
  return did;
}

let timer = null;
function schedule() { clearTimeout(timer); timer = setTimeout(() => sync().catch((e) => fail("capture", e)), 50); }

function questionOf(path) {
  const doc = $("frame").contentDocument;
  return doc ? Array.from(doc.querySelectorAll("[data-bind]")).find((x) => x.dataset.bind === path) : null;
}

function labelOf(path) {
  const q = questionOf(path);
  if (!q) return path;
  const l = q.querySelector(".q-label") || q.querySelector("legend");
  return (l && textOf(l)) || path;
}

// "path: message" from the core's set results into [path, message].
function splitProblem(text) {
  const i = text.indexOf(": ");
  return i > 0 ? [text.slice(0, i), text.slice(i + 2)] : ["", text];
}

function stepLabel(doc) {
  const cur = doc.querySelector(".stepper a[aria-current=step]") || doc.querySelector(".stepper a");
  const t = cur ? cur.textContent.trim() : "";
  if (t && t !== aboutLabel) {
    aboutLabel = t;
    const li = root.querySelector('#pills li[data-pill="about"]');
    if (li) li.textContent = t;
  }
}

async function sync() {
  if (!capture) return;
  const doc = $("frame").contentDocument;
  const entries = readAnswerEntries(doc);
  const now = new Map(entries);
  const changed = [];
  for (const [p, v] of now) if (capture.sent.get(p) !== v) changed.push([p, v]);
  for (const p of capture.sent.keys()) if (!now.has(p)) changed.push([p, '{"clear":true}']);
  if (changed.length) {
    const res = JSON.parse(await call("setValues", "{" + changed.map(([p, v]) => JSON.stringify(p) + ":" + v).join(",") + "}"));
    capture.sent = now;
    capture.view = res.view;
    for (const [p] of changed) capture.problems.delete(p);
    for (const text of res.problems) {
      const [p, m] = splitProblem(text);
      capture.problems.set(p || text, m);
    }
  }
  const ev = JSON.parse(await call("evaluate", capture.options, readAnswers(doc), capture.roster));
  capture.ev = ev;
  applyVisibility(doc, ev.visibility);
  // Answers the rules clear (their question is no longer applicable) are cleared in the form too,
  // so what is shown is what the core holds.
  let cleared = false;
  for (const path of ev.cleared || []) {
    const q = Array.from(doc.querySelectorAll("[data-bind]")).find((x) => x.dataset.bind === path);
    if (q && clearQuestion(q)) cleared = true;
  }
  if (cleared) schedule();
  stepLabel(doc);
  showVerdicts(ev);
}

// Every value problem the core reported, as [label, message]: the page's values, then the
// stored ones.
function problemList() {
  if (!capture) return [];
  const out = [];
  const seen = new Set();
  for (const p of capture.ev ? capture.ev.problems : []) { seen.add(p.path); out.push([labelOf(p.path), p.message]); }
  for (const [p, m] of capture.problems) {
    if (!seen.has(p)) out.push([p ? labelOf(p) : "", m]);
  }
  return out;
}

function hardList() {
  if (!capture) return [];
  return [...new Set([...(capture.view ? capture.view.hard : []), ...(capture.ev ? capture.ev.hard : [])])];
}

function blockedReason() {
  if (!capture) return "";
  const problems = problemList();
  if (problems.length) return problems.map(([l, m]) => (l ? `${l}: ${m}` : m)).join("; ");
  const hard = hardList();
  if (hard.length) return "A rule must be put right first: " + hard.join(", ");
  return "";
}

function showVerdicts(ev) {
  const box = $("verdicts");
  box.replaceChildren();
  for (const [label, message] of problemList()) box.append(el("p", "problem", label ? `${label}: ${message}` : message));
  for (const rule of hardList()) box.append(el("p", "problem", `Put this right before sealing: ${rule}`));
  const v = capture.view || { soft: [] };
  const soft = new Set([...(v.soft || []), ...(ev.soft || [])]);
  for (const rule of soft) {
    const f = el("form");
    const inp = document.createElement("input");
    inp.placeholder = "Reason to keep " + rule;
    inp.setAttribute("aria-label", "Reason to keep " + rule);
    const b = el("button", "btn btn-secondary", "Keep with this reason");
    f.append(el("span", "", `Check: ${rule}.`), inp, b);
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await call("overrideSoft", rule, inp.value);
        log(true, "soft verdict " + rule + " kept with a reason", "check kept with a reason");
        await sync();
      } catch (err) { box.append(el("p", "problem", fail("override", err))); }
    });
    box.append(f);
  }
  const why = blockedReason();
  const go = $("to-review");
  go.disabled = !!why;
  go.title = why;
}

// The window class follows the frame's width; a new class draws the form again with the answers.
let resizeTimer = null;
addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(async () => {
    if (!capture || phase !== "about" || windowClass() === capture.window) return;
    const frame = $("frame");
    const values = "{" + readAnswerEntries(frame.contentDocument).map(([p, v]) => JSON.stringify(p) + ":" + v).join(",") + "}";
    capture.window = windowClass();
    capture.options = optionsFor(capture.window);
    const html = await call("render", capture.options, values, capture.roster);
    const doc = frame.contentDocument;
    doc.open(); doc.write(html); doc.close();
    wire(doc);
    capture.sent = new Map(readAnswerEntries(doc));
    await sync();
  }, 400);
});

$("discard").addEventListener("click", () => {
  $("close-confirm").hidden = false;
  $("discard").hidden = true;
});
$("discard-no").addEventListener("click", () => {
  $("close-confirm").hidden = true;
  $("discard").hidden = false;
});
$("discard-yes").addEventListener("click", async () => {
  await call("discardCapture");
  capture = null;
  log(true, "capture discarded", "capture closed; nothing was saved");
  await toRoster();
});

// A browser cannot protect the screen; cover the form while the tab is hidden.
document.addEventListener("visibilitychange", () => { if (capture && phase === "about") $("capture").hidden = document.hidden; });

// ---- review and seal ------------------------------------------------------------------------

function textOf(node) {
  const c = node.cloneNode(true);
  for (const i of c.querySelectorAll(".icon, .prefix, .from-roster, .badge")) i.remove();
  return c.textContent.replace(/\s+/g, " ").trim();
}

function answerText(q) {
  const nr = q.querySelector(".nr-btn[aria-pressed=true]");
  if (nr) return nr.textContent.trim();
  const picked = Array.from(q.querySelectorAll("input[type=radio]:checked, input[type=checkbox]:checked"));
  if (picked.length) return picked.map((i) => { const l = i.closest("label"); return l ? textOf(l) : i.value; }).join(", ");
  const typed = Array.from(q.querySelectorAll("input:not([type=radio]):not([type=checkbox]), textarea")).filter((i) => i.value !== "");
  if (typed.length) {
    const unit = q.querySelector("select[name^=u]");
    return typed.map((i) => i.value).join(" / ") + (unit ? " " + unit.value : "");
  }
  return null;
}

function goToQuestion(q) {
  const doc = q.ownerDocument;
  const stepEl = q.closest(".step");
  if (stepEl) {
    const link = doc.querySelector(`.stepper a[data-step="${stepEl.dataset.step}"]`);
    if (link) link.click();
  }
  const panel = q.closest("[role=tabpanel]");
  if (panel) {
    const tab = doc.querySelector(`[role=tab][aria-controls="${panel.id}"]`);
    if (tab) tab.click();
  }
  phase = "about";
  paint();
  q.scrollIntoView({ block: "center" });
  const c = q.querySelector("input, select, textarea, button");
  if (c) c.focus({ preventScroll: true });
}

// Hidden by the instrument's rules (not merely on another step or tab of the form).
function hiddenByRules(q) {
  for (let n = q; n && n.nodeType === 1; n = n.parentElement) {
    if (n.style.display === "none") return true;
    if (n.hidden && !n.matches(".step, [role=tabpanel]")) return true;
  }
  return false;
}

function buildReview() {
  const doc = $("frame").contentDocument;
  const out = $("review-out");
  out.replaceChildren();
  const groups = new Map();
  for (const q of doc.querySelectorAll("[data-bind][data-control]")) {
    if (q.dataset.control === "read-only") continue;
    if (hiddenByRules(q)) continue;
    const text = answerText(q);
    if (text === null) continue;
    const card = q.closest("section.card") || q.closest(".step");
    const heading = card && (card.querySelector(".box-title") || card.querySelector(".step-title"));
    const title = heading ? textOf(heading).replace(/^Step \d+ of \d+\s*/, "") : "";
    if (!groups.has(title)) groups.set(title, []);
    groups.get(title).push([q, text]);
  }
  let answered = 0;
  for (const [title, rows] of groups) {
    if (title) out.append(el("div", "cohort", title));
    for (const [q, text] of rows) {
      answered++;
      const row = el("div", "row");
      const edit = el("button", "edit", "Edit");
      edit.type = "button";
      edit.setAttribute("aria-label", "Edit " + labelOf(q.dataset.bind));
      edit.addEventListener("click", () => goToQuestion(q));
      row.append(el("span", "lbl", labelOf(q.dataset.bind)), el("span", "val", text), edit);
      out.append(row);
    }
  }
  if (!answered) out.append(el("p", "note", "Nothing is answered yet."));
  const un = capture.view.unanswered;
  if (un.length) {
    const d = document.createElement("details");
    d.className = "more";
    d.append(el("summary", "", `${un.length} not answered`));
    for (const p of un) {
      const row = el("div", "row gap");
      row.append(el("span", "lbl", labelOf(p)), el("span", "val", "Not answered"));
      const q = questionOf(p);
      if (q) {
        const show = el("button", "edit", "Show");
        show.type = "button";
        show.addEventListener("click", () => goToQuestion(q));
        row.append(show);
      }
      d.append(row);
    }
    out.append(d);
  }
}

function paintSealCard() {
  const n = capture.view.unanswered.length;
  const checks = $("seal-checks");
  checks.replaceChildren();
  const why = blockedReason();
  checks.append(why ? el("li", "bad", why) : el("li", "", "Every rule and value check passed."));
  const soft = capture.view.soft || [];
  if (soft.length) checks.append(el("li", "bad", `${soft.length} check(s) to look at: ${soft.join(", ")}. Keep them with a reason in the form.`));
  if (n) checks.append(el("li", "", `${n} not answered`));
  const ack = $("ack");
  ack.hidden = n === 0;
  ack.setAttribute("aria-pressed", ackChecked ? "true" : "false");
  $("ack-text").textContent = `I have checked: ${n} item${n === 1 ? " stays" : "s stay"} unanswered`;
  const blocked = !!why || (n > 0 && !ackChecked);
  holdSeal.disabled = blocked;
  $("seal").setAttribute("aria-disabled", blocked ? "true" : "false");
  $("seal-confirm").disabled = blocked;
  $("review-title").textContent = `Check the answers for ${capture.name}`;
}

$("ack").addEventListener("click", () => { ackChecked = !ackChecked; paintSealCard(); });

$("to-review").addEventListener("click", async () => {
  try {
    await sync();
    if (blockedReason()) return;
    ackChecked = false;
    $("seal-error").textContent = "";
    buildReview();
    reviewScreen = "review";
    phase = "review";
    paintSealCard();
    paint();
    window.scrollTo(0, 0);
  } catch (x) { fail("review", x); }
});

$("back-to-form").addEventListener("click", () => { phase = "about"; paint(); });

// Hold to confirm: the fill grows while the button is held and fires once full; letting go
// early cancels. Space or Enter held does the same from the keyboard.
const HOLD_MS = 1200;
function holdToConfirm(button, onConfirm) {
  const api = { disabled: false };
  let t0 = null;
  let fire = null;
  let raf = null;
  const paintFill = () => {
    if (t0 === null) return;
    button.style.setProperty("--p", String(Math.min(1, (performance.now() - t0) / HOLD_MS)));
    raf = requestAnimationFrame(paintFill);
  };
  const stop = () => {
    clearTimeout(fire); cancelAnimationFrame(raf);
    t0 = null; fire = null;
    button.style.setProperty("--p", "0");
    button.dataset.holding = "false";
  };
  const begin = () => {
    if (api.disabled || t0 !== null) return;
    t0 = performance.now();
    button.dataset.holding = "true";
    paintFill();
    fire = setTimeout(() => { stop(); onConfirm(); }, HOLD_MS);
  };
  button.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    try { button.setPointerCapture(e.pointerId); } catch { /* synthetic event */ }
    begin();
  });
  for (const t of ["pointerup", "pointercancel", "pointerleave"]) button.addEventListener(t, stop);
  button.addEventListener("keydown", (e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); begin(); } });
  button.addEventListener("keyup", (e) => { if (e.key === " " || e.key === "Enter") stop(); });
  button.addEventListener("blur", stop);
  button.addEventListener("contextmenu", (e) => e.preventDefault());
  // A plain click (for example from assistive technology) does not seal: say how.
  button.addEventListener("click", (e) => {
    e.preventDefault();
    if (!api.disabled) $("seal-error").textContent = "Press and hold the button to seal, or use \"Cannot hold?\" below.";
  });
  return api;
}

async function doSeal() {
  $("seal-error").textContent = "";
  try {
    await sync();
    const why = blockedReason();
    if (why) throw new Error(why);
    const n = capture.view.unanswered.length;
    if (n > 0 && !ackChecked) throw new Error("Confirm that the unanswered items stay unanswered.");
    if (n > 0) await call("acknowledgeIncomplete", n);
    const r = JSON.parse(await call("seal"));
    log(true, `record sealed as seq ${r.seq}: HPKE-sealed journal frame and local record written together (dual write, COL-090..093)`, `record sealed (seq ${r.seq}); written to the journal and the local record`);
    $("sealed-text").textContent = `The record about ${capture.name} is sealed on this device (sequence ${r.seq}) and stays locked here until it is handed over.`;
    capture = null;
    reviewScreen = "sealed";
    phase = "review";
    await loadSummary();
    paint();
  } catch (x) {
    $("seal-error").textContent = fail("seal", x);
  }
}

const holdSeal = holdToConfirm($("seal"), doSeal);

let armed = null;
$("seal-confirm").addEventListener("click", async (e) => {
  if (armed === null) {
    e.target.textContent = "Press again to seal";
    armed = setTimeout(() => { armed = null; e.target.textContent = "Seal now"; }, 5000);
    return;
  }
  clearTimeout(armed); armed = null;
  e.target.textContent = "Seal now";
  await doSeal();
});

$("sealed-next").addEventListener("click", () => toRoster());

// ---- export, upload, clear ------------------------------------------------------------------

async function toExport() {
  await loadSummary();
  const none = summary.records === 0;
  $("export-sum").textContent = none
    ? "Nothing is sealed on this device yet."
    : `${summary.records} sealed record${summary.records === 1 ? "" : "s"} on this device${summary.undelivered ? `, ${summary.undelivered} not yet received by the authority` : ", all received"}.`;
  for (const id of ["upload", "export"]) $(id).disabled = none;
  $("export-out").replaceChildren();
  $("upload-error").textContent = "";
  exportScreen = "ready";
  phase = "export";
  paint();
}

$("export").addEventListener("click", async () => {
  $("export-out").replaceChildren();
  $("upload-error").textContent = "";
  try {
    const r = JSON.parse(await call("export", $("parity").checked));
    lastExportName = r.name;
    const p = document.createElement("p");
    p.textContent = `Export ${r.name}: ${r.records} record(s), seq ${r.from}-${r.through}, ${r.size} bytes, parity ${r.parity ? "on" : "off"}; ${r.label}`;
    $("export-out").prepend(p);
    log(true, `export built and verified before it was offered: ${r.records} record(s), seq ${r.from}-${r.through}`, `export file built and verified: ${r.records} record(s), seq ${r.from}-${r.through}`);
    for (const a of $("export-out").querySelectorAll("a")) { a.download = r.name; a.textContent = "Download " + r.name + " again"; a.click(); }
  } catch (x) { $("upload-error").textContent = fail("export", x); }
});

$("upload").addEventListener("click", async () => {
  $("upload-error").textContent = "";
  $("upload").disabled = true;
  $("upload").textContent = "Uploading...";
  try {
    const r = JSON.parse(await call("upload", uploadUrl));
    const text = `${r.label}. Receipt verified against the trust bundle: covers seq ${r.coveredThrough}; ${r.journalDeleted} cleared frame(s) deleted${r.offerClearThrough ? "; a clear is on offer through " + r.offerClearThrough : ""}.`;
    $("upload-out").textContent = text;
    log(true, "upload: receiver proved its key against the trust bundle; " + text, `upload done; receipt verified, covers seq ${r.coveredThrough}`);
    exportScreen = "done";
    paint();
  } catch (x) { $("upload-error").textContent = fail("upload", x); }
  $("upload").disabled = false;
  $("upload").textContent = "Upload";
});

$("receipt-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  try {
    const r = JSON.parse(await call("importReceipt", new Uint8Array(await f.arrayBuffer())));
    $("upload-out").textContent = `Receipt verified and applied: ${r.journalDeleted} cleared frame(s) deleted${r.offerClearThrough ? "; a clear is on offer through " + r.offerClearThrough : ""}.`;
    log(true, $("upload-out").textContent, "receipt verified and applied");
    exportScreen = "done";
    paint();
  } catch (x) { $("upload-error").textContent = fail("receipt", x); }
  e.target.value = "";
});

$("export-done").addEventListener("click", () => toRoster());
$("export-back").addEventListener("click", () => toRoster());

let clearThrough = 0;
$("clear-preview").addEventListener("click", async () => {
  try {
    clearThrough = await call("lastSeq");
    const r = JSON.parse(await call("clearPreview", clearThrough));
    $("clear-preview-out").textContent = `Clearing through seq ${r.through}: ${r.records} record(s) in the local record, ${r.notReceived} not yet received by the authority. ${r.statement}`;
    $("form-clear").hidden = false;
  } catch (x) { $("clear-preview-out").textContent = fail("clear preview", x); }
});

$("form-clear").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const r = JSON.parse(await call("clear", clearThrough, $("clear-pin1").value, $("clear-pin2").value));
    $("clear-out").textContent = `Cleared: checkpoint seq ${r.checkpoint}; ${r.localDeleted} local entries deleted, ${r.journalDeleted} journal frame(s) deleted under a receipt, ${r.journalKept} kept until a receipt covers them.`;
    log(true, $("clear-out").textContent, "cleared through seq " + clearThrough);
    $("clear-pin1").value = $("clear-pin2").value = "";
    await refresh();
  } catch (x) { $("clear-out").textContent = fail("clear", x); }
});

// "Reset this device" (on the register and session screens) is "Forget this device": a second
// press within five seconds erases the keys, journal and local record from this browser.
for (const b of document.querySelectorAll(".reset-device")) {
  let armed = null;
  b.addEventListener("click", async () => {
    if (armed === null) {
      b.textContent = "Press again to erase this device";
      armed = setTimeout(() => { armed = null; b.textContent = "Reset this device"; }, 5000);
      return;
    }
    await call("forget");
    try { localStorage.clear(); } catch { /* private window */ }
    location.reload();
  });
}

let forgetArmed = null;
$("forget").addEventListener("click", async (e) => {
  if (forgetArmed === null) {
    e.target.textContent = "Press again to delete this device";
    forgetArmed = setTimeout(() => { forgetArmed = null; e.target.textContent = "Forget this device"; }, 5000);
    return;
  }
  await call("forget");
  try { localStorage.clear(); } catch { /* private window */ }
  location.reload();
});

// ---- start ----------------------------------------------------------------------------------

setupBundleScreen();
paint();
(async () => {
  try {
    const res = await fetch("/device/provisioning");
    const p = await res.json();
    if (!res.ok) throw new Error(p.error || "the device is not provisioned");
    uploadUrl = p.uploadUrl;
    const s = await call("start", JSON.stringify(p));
    log(true, `device started (boot ${s.boots}): provisioned with the ${p.authority || "authority"}'s trust bundle (${p.environment || "unspecified"} environment); keys are software keys, unattested`, "device started; software keys, unattested");
    started = true;
    await refresh();
  } catch (err) {
    startError = err && err.message ? err.message : String(err);
    $("unavailable-why").textContent = startError;
    paint();
  }
})();
