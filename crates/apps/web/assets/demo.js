// The guided demo's confirmations (steps 3 to 7). It only reads: the device's own view, which the
// Device page keeps in this browser (device.js, `fs-device-view`), and GET requests through the
// same-origin proxy to the factory. Every value says where it came from. Steps 1 and 2 are
// filled by the server and step 8 confirms nothing.
const $ = (id) => document.getElementById(id);
const section = $("confirmation");
const facts = $("facts");
const status = $("confirm-status");

const DEVICE = "the device's own view";
const FACTORY = "read now from the factory";

function readView() {
  try { return JSON.parse(localStorage.getItem("fs-device-view")) || {}; } catch { return {}; }
}

function say(text) { if (status) status.textContent = text; }

// One confirmed value: a label, the value and where it was read.
function fact(key, label, value, source) {
  let row = facts.querySelector(`[data-fact="${key}"]`);
  if (!row) {
    row = document.createElement("div");
    row.dataset.fact = key;
    row.append(document.createElement("dt"), document.createElement("dd"));
    facts.append(row);
  }
  row.querySelector("dt").textContent = label;
  const dd = row.querySelector("dd");
  const text = document.createElement("span");
  text.className = "value";
  text.textContent = String(value);
  dd.replaceChildren(text);
  if (source) tag(row, source);
  return row;
}

// A label beside a value: where it was read, or a cross-check.
function tag(row, text) {
  const t = document.createElement("span");
  t.className = "tag";
  t.textContent = text;
  row.querySelector("dd").append(" ", t);
}

function clear() { facts.replaceChildren(); }

async function registration(tenancy) {
  try {
    const r = await fetch("/proxy/factory/v1/registrations/" + tenancy);
    if (r.status === 404) return { state: "unknown to the factory" };
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

function noDevice() {
  clear();
  say("This browser has no device yet. Do the earlier steps on the Device page; this page then fills in.");
}

function consentText(c) {
  return Object.entries(c || {}).map(([k, v]) => `${v} ${k}`).join(", ") || "none";
}

// Step 3: the tenancy (the device's) and its state (the factory's).
async function step3() {
  const v = readView();
  if (!v.tenancy) return noDevice();
  const link = $("check-registration");
  if (link) link.href = "/registration?tenancy=" + v.tenancy;
  const r = await registration(v.tenancy);
  clear();
  fact("tenancy", "Tenancy", v.tenancy, DEVICE);
  fact("state", "Registration state", r ? r.state : "the factory could not be reached", FACTORY);
  fact("keys", "Key protection", "Unattested software device (development policy allows it)", DEVICE);
  say(r && r.state === "registered" ? "The factory reports this device as registered." : "The factory does not report this device as registered yet; this page asks again every few seconds.");
  if (!(r && r.state === "registered")) setTimeout(step3, 3000);
}

function describe(p) {
  return `${p.kind} ${p.name} ${p.version}: ${p.signatures} of ${p.threshold} publisher signatures, ${p.logProofs} log inclusion proof(s) against a checkpoint of ${p.checkpointSize} entries`;
}

async function inStep2(address) {
  try {
    const page = await (await fetch("/demo/2")).text();
    return page.includes(address) || page.includes(address.replace(/^sha256:/, ""));
  } catch { return false; }
}

// Step 4: the first bundle the device fetched, as the device received and verified it.
async function step4() {
  const v = readView();
  const b = (v.bundles || [])[0];
  if (!v.tenancy || !b) {
    clear();
    say(v.tenancy ? "The device holds no bundle from the factory yet. Open the Device page; it asks the factory when the device is registered." : "This browser has no device yet.");
    return;
  }
  clear();
  fact("sequence", "Bundle sequence", b.sequence, DEVICE + ", from the factory's response headers");
  fact("file", "Bundle file name", b.file || "(not sent)", DEVICE + ", from the factory's response headers");
  fact("tenancy", "Tenancy", v.tenancy.slice(0, 16) + "...", DEVICE);
  fact("verified", "Verification", "signature, publisher threshold and log inclusion passed; the device refuses a bundle that fails any", DEVICE);
  for (const [i, p] of (b.publications || []).entries()) {
    const row = fact("publication-" + i, "Publication " + (i + 1), describe(p) + " (" + p.address + ")", DEVICE);
    const found = await inStep2(p.address);
    tag(row, found ? "listed in step 2" : "not found in step 2");
  }
  say(`The device holds bundle ${b.sequence}. Find that sequence in the factory's own output below.`);
}

// Step 5: the newest bundle's rosters, as counts only.
function step5() {
  const v = readView();
  const all = v.bundles || [];
  const b = all[all.length - 1];
  if (!v.tenancy || !b) {
    clear();
    say("The device holds no bundle yet (steps 3 and 4).");
    return;
  }
  clear();
  fact("sequence", "Bundle sequence held", b.sequence, DEVICE);
  if (all.length > 1) fact("earlier", "Earlier bundle", all[all.length - 2].sequence, DEVICE);
  for (const [i, r] of (b.rosters || []).entries()) {
    fact("roster-" + i, `Roster ${r.cohort}`, `version ${r.version}, ${r.subjects} subject(s); consent: ${consentText(r.consent)}`, DEVICE);
  }
  fact("dropped", "Roster fields", "fields the instrument does not read are dropped before sealing (DIS-013)", DEVICE);
  say(all.length > 1
    ? `The device holds bundle ${b.sequence}, built after the roster was issued; it replaced bundle ${all[all.length - 2].sequence}.`
    : "The device still holds its first bundle. After roster issue, press Check for a newer bundle on the Device page.");
}

// Step 6: the device's journal.
function step6() {
  const v = readView();
  const j = v.journal;
  if (!v.tenancy || !j) {
    clear();
    say("The device has sealed no record yet.");
    return;
  }
  clear();
  fact("records", "Sealed records", j.records, DEVICE);
  fact("range", "Sequence range", j.records ? `${j.from} to ${j.through}` : "none", DEVICE);
  fact("undelivered", "Not yet received by the authority", j.undelivered, DEVICE);
  say("This is the device's own count. Step 7 confirms the same records with a receipt signed by the intake app.");
}

// Step 7: the export and the receipt the device verified.
function step7() {
  const v = readView();
  if (!v.tenancy || (!v.export && !v.upload)) {
    clear();
    say("Nothing has been exported or uploaded from this device yet.");
    return;
  }
  clear();
  if (v.export) {
    fact("export-name", "Export file", v.export.name, DEVICE);
    fact("export-records", "Records and sequence range", `${v.export.records} record(s), ${v.export.from} to ${v.export.through}`, DEVICE);
    fact("export-size", "Size", `${v.export.size} bytes`, DEVICE);
    fact("export-sha256", "SHA-256", v.export.sha256 || "(not computed)", DEVICE);
  }
  if (v.upload) {
    fact("receipt", "Receipt", "verified in the browser against the trust bundle (signed by the intake app's receipt key)", DEVICE);
    fact("covered", "Covered through sequence", v.upload.coveredThrough, DEVICE);
  }
  say("The receipt is checked by the device, not by this page. The results reader (step 8) shows what landed.");
}

const STEPS = { 3: step3, 4: step4, 5: step5, 6: step6, 7: step7 };
if (section && facts) {
  const run = STEPS[Number(section.dataset.step)];
  if (run) run();
}
