// Live evaluation for the instrument page. The rules are evaluated in the browser by the
// WebAssembly core (the same Rust code the CLI and services run); nothing is sent to the server.
// Reads the answers from the rendered instrument in the same-origin frame, asks the core for
// the result, applies visibility to the frame and writes the verdicts into the page.
import init, { Workbench } from "/assets/wasm/fieldseal_wasm.js";
import { readAnswers, applyVisibility } from "/assets/answers.js";

const panel = document.getElementById("live");
const status = document.getElementById("live-status");
const result = document.getElementById("live-result");
const frame = document.querySelector("iframe.instrument");
const id = panel.dataset.instrument;

function line(term, text) {
  const dt = document.createElement("dt");
  dt.textContent = term;
  const dd = document.createElement("dd");
  dd.textContent = text;
  const item = document.createElement("div");
  item.append(dt, dd);
  result.append(item);
}

function show(r) {
  result.replaceChildren();
  const list = (a) => (a.length ? a.join(", ") : "none");
  line("Hard rules failing", `${r.hard.length}: ${list(r.hard)}`);
  line("Soft rules", `${r.soft.length}: ${list(r.soft)}`);
  line("Value problems", `${r.problems.length}: ${list(r.problems.map((p) => `${p.path} (${p.id}) ${p.message}`))}`);
  line("Unanswered", `${r.unanswered.length}`);
  line("Blocks sealing", r.blocksSealing ? "yes" : "no");
}

async function text(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: ${response.status}`);
  return response.text();
}

async function start() {
  await init();
  const base = `/instruments/${encodeURIComponent(id)}`;
  const wb = new Workbench(await text(`${base}/source`), panel.dataset.format);
  const layouts = panel.dataset.layouts ? panel.dataset.layouts.split(",") : [];
  for (const entry of layouts) {
    const [i, format] = entry.split(":");
    wb.addLayout(await text(`${base}/layout/${i}/source`), format);
  }
  // The survey's cohort is the one the device's bundle assigns it (the device keeps that in this browser).
  let cohort = "";
  try { cohort = ((JSON.parse(localStorage.getItem("fs-device-view")).surveys || []).find((s) => s.survey === id) || {}).cohort || ""; } catch { /* no device here */ }
  const roster = await text(`${base}/roster${cohort ? "?cohort=" + encodeURIComponent(cohort) : ""}`);
  // Null is not a value in the canonical data model: leave the field out instead.
  const choice = { languages: panel.dataset.lang ? [panel.dataset.lang] : [] };
  if (panel.dataset.window) choice.window = panel.dataset.window;
  const wanted = new URLSearchParams(location.search).get("layout");
  // The page lists only the layouts being shown; the core numbers them in the order added.
  if (wanted !== null && /^\d+$/.test(wanted)) {
    const at = layouts.findIndex((entry) => entry.split(":")[0] === wanted);
    if (at >= 0) choice.layout = at;
  }
  const options = JSON.stringify(choice);

  let timer = null;
  function update() {
    const doc = frame.contentDocument;
    if (!doc || !doc.body) return;
    try {
      const r = JSON.parse(wb.evaluate(options, readAnswers(doc), roster));
      applyVisibility(doc, r.visibility);
      show(r);
      status.textContent = "Evaluated in this browser by the WebAssembly core; nothing is sent to the server.";
    } catch (e) {
      status.textContent = "Evaluation failed: " + e;
    }
  }
  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(update, 0);
  }
  function attach() {
    const doc = frame.contentDocument;
    if (!doc) return;
    for (const type of ["input", "change", "click"]) doc.addEventListener(type, schedule);
    update();
  }
  frame.addEventListener("load", attach);
  if (frame.contentDocument && frame.contentDocument.readyState === "complete" && frame.contentDocument.body && frame.contentDocument.body.children.length) attach();
}

start().catch((e) => {
  status.textContent = "Live evaluation could not start: " + e;
});
