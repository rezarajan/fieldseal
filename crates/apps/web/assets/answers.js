// Reading answers out of the html adapter's controls and applying visibility to its nodes.
// Shared by the instrument page (live evaluation) and the device page (capture).

const CANONICAL = /^-?\d+(\.\d+)?$/;

// A canonical number string as a JSON number, built from the typed digits (no float round trip).
function jsonNumber(text) {
  if (!CANONICAL.test(text)) return null;
  return text.replace(/^(-?)0+(?=\d)/, "$1");
}

// The answer of one question element as JSON text, or null when unanswered.
export function readQuestion(q) {
  const pressed = q.querySelector(".nr-btn[aria-pressed=true]");
  if (pressed) return '{"nr":' + JSON.stringify(pressed.dataset.nr) + "}";
  const control = q.dataset.control;
  const radio = q.querySelector("input[type=radio]:checked");
  if (radio) {
    if (control === "yes-no" && (radio.value === "true" || radio.value === "false")) return radio.value;
    return JSON.stringify(radio.value);
  }
  if (q.querySelector("input[type=radio]")) return null;
  const boxes = q.querySelectorAll("input[type=checkbox]");
  if (boxes.length) {
    const on = Array.from(boxes).filter((b) => b.checked).map((b) => JSON.stringify(b.value));
    return on.length ? "[" + on.join(",") + "]" : null;
  }
  const typed = Array.from(q.querySelectorAll("input[data-number]"));
  if (typed.length) {
    const numbers = typed.map((i) => jsonNumber(i.getAttribute("data-canonical") || ""));
    if (numbers.some((n) => n === null)) return null;
    return typed.length === 1 ? numbers[0] : "[" + numbers.join(",") + "]";
  }
  const stepper = q.querySelector("input[type=number]");
  if (stepper) return stepper.value === "" ? null : jsonNumber(stepper.value);
  const field = q.querySelector("input[type=date], input[type=text], textarea");
  if (field) return field.value === "" ? null : JSON.stringify(field.value);
  return null;
}

// Every answer as [item path, JSON text] pairs (and `<path>.unit` when the entry unit differs
// from the item's own, which is the first option). The JSON text is kept as typed, so a number
// such as 2.50 keeps its digits.
export function readAnswerEntries(doc) {
  const out = [];
  for (const q of doc.querySelectorAll("[data-bind][data-control]")) {
    const path = q.dataset.bind;
    const value = readQuestion(q);
    if (value !== null) out.push([path, value]);
    const unit = q.querySelector("select[name^=u]");
    if (unit && unit.selectedIndex > 0) out.push([path + ".unit", JSON.stringify(unit.value)]);
  }
  return out;
}

// All answers as one JSON object text, keyed by item path.
export function readAnswers(doc) {
  return "{" + readAnswerEntries(doc).map(([p, v]) => JSON.stringify(p) + ":" + v).join(",") + "}";
}

const CONTROLS = "input, select, textarea, button";

// Applies visibility by plan node id: hidden elements are hidden, protected ones stay visible
// but disabled and greyed. Styles are set through the CSS object model, which the frame's own
// content security policy allows.
export function applyVisibility(doc, visibility) {
  // The "not applicable now" badge is drawn with the page, on nodes that were protected then.
  // Remember which badges those are (the first call sees the page as drawn), so that they follow
  // the node when the rules make it applicable.
  for (const b of doc.querySelectorAll(".badge:not([data-pb])")) b.dataset.pb = b.closest(".is-protected") ? "1" : "0";
  for (const el of doc.querySelectorAll("[data-node]")) {
    const v = visibility[el.dataset.node];
    if (!v) continue;
    // A form's own steps and tabs are shown and hidden by its navigation (the `hidden`
    // attribute); a rule only adds or removes `display: none` on them.
    if (!el.matches(".step, [role=tabpanel]")) el.hidden = v === "hidden";
    el.style.display = v === "hidden" ? "none" : "";
    el.style.opacity = v === "protected" ? "0.55" : "";
    el.classList.toggle("is-protected", v === "protected");
    const targets = [el, ...el.querySelectorAll(CONTROLS)];
    for (const c of targets) {
      if (!(c.matches(CONTROLS) || c.tagName === "FIELDSET")) continue;
      if (v === "protected") {
        if (!c.disabled) { c.disabled = true; c.dataset.liveDisabled = "1"; }
      } else if (c.dataset.liveDisabled || (c.disabled && !c.closest(".step-nav"))) {
        // Controls drawn disabled (their question was not applicable when the page was drawn)
        // are enabled once the rules make it applicable; the form's own Back button is not one.
        c.disabled = false;
        delete c.dataset.liveDisabled;
      }
    }
  }
  for (const b of doc.querySelectorAll(".badge[data-pb='1']")) b.style.display = b.closest(".is-protected") ? "" : "none";
}
