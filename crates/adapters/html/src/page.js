(function () {
  "use strict";
  var doc = document;
  var root = doc.documentElement;
  root.classList.remove("no-js");
  root.classList.add("js");

  // Steps: one at a time. A linear step is reachable once every step before it has been
  // shown; a free step always is (INS-205). Going back is always allowed.
  var steps = Array.prototype.slice.call(doc.querySelectorAll(".step"));
  var links = Array.prototype.slice.call(doc.querySelectorAll(".stepper a"));
  var current = 0;
  var reached = 0;
  function reachable(i) {
    return i <= reached || steps[i].getAttribute("data-navigation") === "free";
  }
  function show(i, focus) {
    if (i < 0 || i >= steps.length || !reachable(i) && i !== reached + 1) return;
    current = i;
    if (i > reached) reached = i;
    steps.forEach(function (s, j) { s.hidden = j !== i; });
    links.forEach(function (a, j) {
      if (j === i) a.setAttribute("aria-current", "step"); else a.removeAttribute("aria-current");
      if (reachable(j)) a.removeAttribute("aria-disabled"); else a.setAttribute("aria-disabled", "true");
    });
    steps.forEach(function (s, j) {
      var back = s.querySelector(".step-nav .back");
      var next = s.querySelector(".step-nav .next");
      if (back) back.disabled = j === 0;
      if (next) next.hidden = j === steps.length - 1;
    });
    if (focus) {
      var h = steps[i].querySelector(".step-title");
      if (h) h.focus();
    }
  }
  links.forEach(function (a, j) {
    a.addEventListener("click", function (e) {
      e.preventDefault();
      if (reachable(j)) show(j, true);
    });
  });
  steps.forEach(function (s, j) {
    var back = s.querySelector(".step-nav .back");
    var next = s.querySelector(".step-nav .next");
    if (back) back.addEventListener("click", function () { show(j - 1, true); });
    if (next) next.addEventListener("click", function () { show(j + 1, true); });
  });
  // A `#step-N` link opens that step, as a stepper link would without the script.
  var linked = /^#step-(\d+)$/.exec(location.hash);
  var first = linked ? Math.min(parseInt(linked[1], 10), steps.length - 1) : 0;
  if (first > reached) reached = first;
  if (steps.length) show(first, false);

  // Tabs: the ARIA tabs pattern, always freely navigable (INS-205).
  Array.prototype.forEach.call(doc.querySelectorAll(".tabs"), function (box) {
    var list = box.querySelector(".tablist");
    if (!list) return;
    var tabs = Array.prototype.slice.call(list.querySelectorAll("[role=tab]"));
    function select(i, focus) {
      tabs.forEach(function (t, j) {
        var on = j === i;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
        var panel = doc.getElementById(t.getAttribute("aria-controls"));
        if (panel) panel.hidden = !on;
      });
      if (focus) tabs[i].focus();
    }
    tabs.forEach(function (t, j) {
      t.addEventListener("click", function () { select(j, false); });
    });
    list.addEventListener("keydown", function (e) {
      var i = tabs.indexOf(doc.activeElement);
      if (i < 0) return;
      var rtl = getComputedStyle(list).direction === "rtl";
      var forward = rtl ? "ArrowLeft" : "ArrowRight";
      var backward = rtl ? "ArrowRight" : "ArrowLeft";
      var n = null;
      if (e.key === forward) n = (i + 1) % tabs.length;
      else if (e.key === backward) n = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === "Home") n = 0;
      else if (e.key === "End") n = tabs.length - 1;
      if (n !== null) {
        e.preventDefault();
        select(n, true);
      }
    });
    if (tabs.length) select(0, false);
  });
  var refreshQuestion = function () {};
  // Nonresponse: separate buttons, never options. Pressing one clears the question's answer
  // and marks it; answering afterwards withdraws the nonresponse (INS-021).
  Array.prototype.forEach.call(doc.querySelectorAll(".nr"), function (box) {
    var question = box.parentNode;
    var buttons = Array.prototype.slice.call(box.querySelectorAll(".nr-btn"));
    function clearAnswer() {
      Array.prototype.forEach.call(question.querySelectorAll("input, select, textarea"), function (c) {
        if (c.type === "radio" || c.type === "checkbox") c.checked = false; else c.value = "";
        c.removeAttribute("data-canonical");
        c.removeAttribute("aria-invalid");
      });
      refreshQuestion(question);
    }
    function withdraw() {
      buttons.forEach(function (b) { b.setAttribute("aria-pressed", "false"); });
    }
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        var on = b.getAttribute("aria-pressed") !== "true";
        withdraw();
        if (on) {
          clearAnswer();
          b.setAttribute("aria-pressed", "true");
        }
      });
    });
    question.addEventListener("input", withdraw);
    question.addEventListener("change", function (e) {
      if (!box.contains(e.target)) withdraw();
    });
  });
  // ---- Numbers -----------------------------------------------------------------------
  // Typed text is read with the language's digits and separators (INS-088) and shown back in
  // them; the locale-free value is kept in `data-canonical`, which is all the capture glue
  // reads. A value outside its bounds, off its grid or with too many decimals never gets a
  // canonical value (INS-027, INS-163, INS-070, INS-162): it is refused, or kept on screen
  // flagged and unread. `canonical` mirrors `LocaleFormatter::parse_number`, the reference.
  var body = doc.body;
  var digits = Array.from(body.getAttribute("data-digits") || "0123456789");
  var decimal = body.getAttribute("data-decimal") || ".";
  var group = body.getAttribute("data-group") || ",";
  var minus = body.getAttribute("data-minus") || "-";
  var spaces = /\s/.test(group) ? [" ", "\u00a0", "\u202f", "\u2009"] : [];
  var PLAIN = /^-?\d+(\.\d+)?$/;
  function digitOf(c) {
    var i = digits.indexOf(c);
    if (i >= 0) return i;
    var n = c.charCodeAt(0);
    if (n >= 0x30 && n <= 0x39) return n - 0x30;
    if (n >= 0x660 && n <= 0x669) return n - 0x660;
    if (n >= 0x6f0 && n <= 0x6f9) return n - 0x6f0;
    return -1;
  }
  function canonical(text) {
    var t = text.replace(/[\u200e\u200f\u061c\u2066-\u2069]/g, "").trim();
    var negative = false;
    [minus, "-", "\u2212"].some(function (m) {
      if (m && t.indexOf(m) === 0) { t = t.slice(m.length).replace(/^\s+/, ""); negative = true; return true; }
      return false;
    });
    var whole = "", fraction = "", seenDecimal = false, groups = [0];
    for (var c of t) {
      var d = digitOf(c);
      if (d >= 0) {
        if (seenDecimal) fraction += d; else { whole += d; groups[groups.length - 1] += 1; }
      } else if (c === decimal && !seenDecimal) {
        seenDecimal = true;
      } else if ((c === group || spaces.indexOf(c) >= 0) && !seenDecimal) {
        groups.push(0);
      } else {
        return null;
      }
    }
    var ok = groups.length === 1 || (groups[0] >= 1 && groups[0] <= 3 &&
      groups.slice(1).every(function (g) { return g === 2 || g === 3; }) &&
      (groups[groups.length - 1] === 3 || groups.length > 2));
    if (!whole || !ok || (seenDecimal && !fraction)) return null;
    return (negative ? "-" : "") + whole + (seenDecimal ? "." + fraction : "");
  }
  function native(canon) {
    return Array.from(canon).map(function (c) {
      return c === "." ? decimal : c === "-" ? minus : digits[c.charCodeAt(0) - 0x30];
    }).join("");
  }

  // Exact decimals, no float round trip: a decimal is {n: BigInt, s: scale}.
  var ZERO = BigInt(0), TEN = BigInt(10);
  function dec(source) {
    var m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(source || "");
    if (!m) return null;
    var frac = m[3] || "";
    var n = BigInt(m[2] + frac);
    return { n: m[1] ? -n : n, s: frac.length };
  }
  function scaled(a, s) { return a.n * (TEN ** BigInt(s - a.s)); }
  function cmp(a, b) {
    var s = Math.max(a.s, b.s);
    var x = scaled(a, s), y = scaled(b, s);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  function add(a, b, sign) {
    var s = Math.max(a.s, b.s);
    return { n: scaled(a, s) + (sign < 0 ? -scaled(b, s) : scaled(b, s)), s: s };
  }
  function fractionDigits(a) {
    var n = a.n < ZERO ? -a.n : a.n, s = a.s;
    while (s > 0 && n % TEN === ZERO) { n = n / TEN; s -= 1; }
    return s;
  }
  function plain(a) {
    var neg = a.n < ZERO, t = (neg ? -a.n : a.n).toString();
    while (t.length <= a.s) t = "0" + t;
    var out = a.s ? t.slice(0, -a.s) + "." + t.slice(-a.s) : t;
    return (neg ? "-" : "") + out;
  }
  function message(name, fills) {
    var t = body.getAttribute("data-msg-" + name) || "";
    Object.keys(fills || {}).forEach(function (k) { t = t.split("{" + k + "}").join(fills[k]); });
    return t;
  }

  // The inline message of a question (`.field-error`, which every control is described by).
  function questionOf(el) { return el.closest(".q"); }
  function showMessage(q) {
    if (!q) return;
    var m = q.querySelector(".field-error");
    if (!m) return;
    var t = "";
    [q].concat(Array.prototype.slice.call(q.querySelectorAll("input, textarea, .pair"))).some(function (c) {
      if (c.fsMsg) { t = c.fsMsg; return true; }
      return false;
    });
    m.textContent = t;
    m.hidden = !t;
  }
  function flag(el, msg, invalid) {
    el.fsMsg = msg || null;
    if (invalid) el.setAttribute("aria-invalid", "true"); else el.removeAttribute("aria-invalid");
    showMessage(questionOf(el));
  }
  function setCanonical(input, canon) {
    if (canon === null) input.removeAttribute("data-canonical"); else input.setAttribute("data-canonical", canon);
  }
  function entryUnitChanged(el) {
    var q = questionOf(el);
    var u = q && q.querySelector("select[name^=u]");
    return !!u && u.selectedIndex > 0;
  }

  // The first rule a canonical value breaks, or null: {kind, text}.
  function violation(input, canon) {
    var v = dec(canon);
    if (!v) return { kind: "number", text: message("number") };
    var places = input.getAttribute("data-decimals");
    if (places === null) places = input.getAttribute("data-minor-digits");
    if (places !== null && fractionDigits(v) > parseInt(places, 10)) {
      return { kind: "decimals", text: message("decimals", { n: native(String(parseInt(places, 10))) }) };
    }
    // In another entry unit the core converts exactly and checks the bounds (INS-161).
    if (entryUnitChanged(input)) return null;
    var hi = dec(input.getAttribute("data-max")), lo = dec(input.getAttribute("data-min"));
    if (hi && cmp(v, hi) > 0) return { kind: "high", text: input.getAttribute("data-msg-high") };
    if (lo && cmp(v, lo) < 0) return { kind: "low", text: input.getAttribute("data-msg-low") };
    var step = dec(input.getAttribute("data-step")), start = dec(input.getAttribute("data-start"));
    if (input.type === "number" && step && start && step.n > ZERO) {
      var s = Math.max(v.s, start.s, step.s);
      if ((scaled(v, s) - scaled(start, s)) % scaled(step, s) !== ZERO) {
        return { kind: "step", text: message("step", { step: native(plain(step)) }) };
      }
    }
    return null;
  }

  // A number field read in the language's digits. While typing, only what typing more cannot
  // fix is reported; on commit (`final`) everything is.
  function checkText(input, final) {
    var raw = input.value.trim();
    if (!raw) {
      setCanonical(input, null);
      flag(input, null, false);
      return;
    }
    var canon = canonical(raw);
    if (canon === null) {
      setCanonical(input, null);
      flag(input, final ? message("number") : null, final);
      return;
    }
    var bad = violation(input, canon);
    if (bad) {
      setCanonical(input, null);
      var now = final || bad.kind === "high" || bad.kind === "decimals";
      flag(input, now ? bad.text : null, now);
      return;
    }
    setCanonical(input, canon);
    flag(input, null, false);
    if (final) input.value = native(canon);
  }

  // A stepper's own field (type=number): a value that cannot be entered is put back to the last
  // good one; one that may still become valid is kept, flagged and unread until it does.
  function revert(input, good, msg) {
    input.value = good === null ? "" : good;
    setCanonical(input, good);
    flag(input, msg, false);
  }
  function checkNumber(input, final) {
    var good = input.fsGood === undefined ? null : input.fsGood;
    var t = input.value.trim();
    if (t === "") {
      setCanonical(input, null);
      if (input.validity && input.validity.badInput) {
        if (final) revert(input, good, message("number"));
        return;
      }
      input.fsGood = null;
      // A refusal said while typing stays on screen until the next edit.
      if (!final) flag(input, null, false);
      return;
    }
    if (!PLAIN.test(t)) {
      setCanonical(input, null);
      if (final) revert(input, good, message("number"));
      return;
    }
    var bad = violation(input, t);
    if (!bad) {
      input.fsGood = t;
      setCanonical(input, t);
      if (!final) flag(input, null, false);
    } else if (final || bad.kind === "high" || bad.kind === "decimals") {
      revert(input, good, bad.text);
    } else {
      setCanonical(input, null);
      flag(input, bad.text, true);
    }
  }

  // Bounded steppers: - / value / +, a button off at its bound. Either button, used first, sets
  // the start value, which is not written until then (INS-022).
  function syncStepper(box) {
    var input = box.querySelector("input");
    if (!input) return;
    var canon = dec(input.getAttribute("data-canonical"));
    var lo = dec(input.getAttribute("data-min")), hi = dec(input.getAttribute("data-max"));
    Array.prototype.forEach.call(box.querySelectorAll(".num-stepper__btn"), function (b) {
      var down = b.getAttribute("data-dir") === "-1";
      var off = input.disabled || !!(canon && (down ? lo && cmp(canon, lo) <= 0 : hi && cmp(canon, hi) >= 0));
      if (b.disabled !== off) b.disabled = off;
    });
  }
  function press(box, dir) {
    var input = box.querySelector("input");
    var canon = dec(input.getAttribute("data-canonical"));
    var step = dec(input.getAttribute("data-step")) || { n: BigInt(1), s: 0 };
    var next = canon ? add(canon, step, dir) : dec(input.getAttribute("data-start"));
    if (!next) return;
    var lo = dec(input.getAttribute("data-min")), hi = dec(input.getAttribute("data-max"));
    if ((hi && cmp(next, hi) > 0) || (lo && cmp(next, lo) < 0)) return;
    while (next.s > 0 && next.n % TEN === ZERO) next = { n: next.n / TEN, s: next.s - 1 };
    var value = plain(next);
    input.value = input.type === "number" ? value : native(value);
    input.fsGood = value;
    setCanonical(input, value);
    flag(input, null, false);
    syncStepper(box);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }
  Array.prototype.forEach.call(doc.querySelectorAll(".num-stepper"), function (box) {
    box.addEventListener("click", function (e) {
      var b = e.target.closest ? e.target.closest(".num-stepper__btn") : null;
      if (b && !b.disabled) press(box, parseInt(b.getAttribute("data-dir"), 10));
    });
    box.addEventListener("input", function () { syncStepper(box); });
    box.addEventListener("change", function () { syncStepper(box); });
    // The visibility glue switches buttons off and on too: keep them true to the bounds.
    if (window.MutationObserver) {
      new MutationObserver(function () { syncStepper(box); }).observe(box, { attributes: true, attributeFilter: ["disabled"], subtree: true });
    }
  });
  // An arrow key on an empty stepper sets its start value, not the browser's own step.
  Array.prototype.forEach.call(doc.querySelectorAll("input[data-start]"), function (input) {
    input.addEventListener("keydown", function (e) {
      if ((e.key === "ArrowUp" || e.key === "ArrowDown") && input.value === "") {
        e.preventDefault();
        var box = input.closest(".num-stepper");
        if (box) { press(box, 1); return; }
        input.value = input.getAttribute("data-start");
        input.dispatchEvent(new Event("input", { bubbles: true }));
      }
    });
  });

  Array.prototype.forEach.call(doc.querySelectorAll("input[data-number]"), function (input) {
    var isNumber = input.type === "number";
    input.addEventListener("input", function () { if (isNumber) checkNumber(input, false); else checkText(input, false); });
    input.addEventListener("change", function () { if (isNumber) checkNumber(input, true); else checkText(input, true); });
    var q = questionOf(input);
    var unit = q && q.querySelector("select[name^=u]");
    if (unit && !unit.fsBound) {
      unit.fsBound = true;
      unit.addEventListener("change", function () {
        Array.prototype.forEach.call(q.querySelectorAll("input[data-number]"), function (i) {
          if (i.type === "number") checkNumber(i, true); else checkText(i, true);
        });
        tolerance(q);
      });
    }
    // A value the page was drawn with is read the same way as a typed one.
    if (input.value.trim()) { if (isNumber) checkNumber(input, true); else checkText(input, true); }
  });

  // Two readings (INS-026): a difference over the tolerance is not refused. It is a hard verdict
  // of the core, so both readings stay and the page says so.
  function tolerance(q) {
    var pair = q.querySelector(".pair[data-tolerance]");
    if (!pair) return;
    var fields = pair.querySelectorAll("input");
    var a = dec(fields[0].getAttribute("data-canonical"));
    var b = dec(fields[1].getAttribute("data-canonical"));
    var limit = dec(pair.getAttribute("data-tolerance"));
    var off = false;
    if (a && b && limit && !entryUnitChanged(pair)) {
      var d = add(a, b, -1);
      if (d.n < ZERO) d = { n: -d.n, s: d.s };
      off = cmp(d, limit) > 0;
    }
    flag(pair, off ? pair.getAttribute("data-msg-tolerance") : null, false);
    Array.prototype.forEach.call(fields, function (i) {
      if (off) i.setAttribute("aria-invalid", "true");
      else if (!i.fsMsg) i.removeAttribute("aria-invalid");
    });
  }
  Array.prototype.forEach.call(doc.querySelectorAll(".pair[data-tolerance]"), function (pair) {
    var q = questionOf(pair);
    pair.addEventListener("input", function () { tolerance(q); });
    pair.addEventListener("change", function () { tolerance(q); });
    tolerance(q);
  });

  // Dates (INS-027): a date outside its bounds is reported as soon as it is complete, and the
  // field is emptied when the collector leaves it.
  function checkDate(input, leaving) {
    var v = input.value;
    var lo = input.getAttribute("min"), hi = input.getAttribute("max");
    var msg = null;
    if (v && hi && v > hi) msg = input.getAttribute("data-msg-high");
    else if (v && lo && v < lo) msg = input.getAttribute("data-msg-low");
    if (msg && leaving) {
      input.value = "";
      flag(input, msg, false);
      input.dispatchEvent(new Event("change", { bubbles: true }));
    } else {
      flag(input, msg, !!msg);
    }
  }
  Array.prototype.forEach.call(doc.querySelectorAll("input[type=date]"), function (input) {
    input.addEventListener("input", function () { checkDate(input, false); });
    input.addEventListener("change", function () { checkDate(input, false); });
    input.addEventListener("blur", function () { checkDate(input, true); });
  });

  // Multi-choice with a maximum (INS-025): a live count, and at the limit the other options are
  // unavailable until one is unticked. An exclusive code deselects every other, and any other
  // deselects it (INS-133); it stays available at the limit, since choosing it frees the rest.
  Array.prototype.forEach.call(doc.querySelectorAll(".options"), function (list) {
    var boxes = Array.prototype.slice.call(list.querySelectorAll("input[type=checkbox]"));
    if (!boxes.length) return;
    var q = questionOf(list);
    var max = list.hasAttribute("data-max") ? parseInt(list.getAttribute("data-max"), 10) : null;
    var out = q && q.querySelector(".choice-count");
    function sync() {
      var chosen = boxes.filter(function (b) { return b.checked; }).length;
      var full = max !== null && chosen >= max;
      boxes.forEach(function (b) {
        var label = b.closest("label");
        var closed = full && !b.checked && !b.hasAttribute("data-exclusive");
        if (closed && !b.disabled) { b.disabled = true; b.setAttribute("data-limit", "1"); }
        if (!closed && b.hasAttribute("data-limit")) { b.disabled = false; b.removeAttribute("data-limit"); }
        if (label) label.classList.toggle("is-unavailable", b.hasAttribute("data-limit"));
      });
      list.classList.toggle("is-full", full);
      if (out) out.textContent = (out.getAttribute("data-template") || "").split("{n}").join(native(String(chosen)));
      if (max !== null && q) {
        var over = chosen > max;
        q.fsMsg = over && out ? out.getAttribute("data-msg-high") : null;
        if (over) q.setAttribute("aria-invalid", "true"); else q.removeAttribute("aria-invalid");
        showMessage(q);
      }
    }
    list.addEventListener("change", function (e) {
      var t = e.target;
      if (t.type === "checkbox" && t.checked) {
        boxes.forEach(function (b) {
          if (b !== t && (t.hasAttribute("data-exclusive") || b.hasAttribute("data-exclusive"))) b.checked = false;
        });
      }
      sync();
    });
    list.fsSync = sync;
    sync();
  });

  // Anything that clears a question's answer from outside (a nonresponse) lets the controls,
  // counts and messages catch up.
  refreshQuestion = function (q) {
    Array.prototype.forEach.call(q.querySelectorAll(".options"), function (l) { if (l.fsSync) l.fsSync(); });
    [q].concat(Array.prototype.slice.call(q.querySelectorAll("input, textarea, .pair"))).forEach(function (c) {
      c.fsMsg = null;
      c.removeAttribute("aria-invalid");
      if (c.fsGood !== undefined) c.fsGood = null;
    });
    Array.prototype.forEach.call(q.querySelectorAll(".num-stepper"), syncStepper);
    showMessage(q);
  };

  // The capture glue shows what the core refused (for example INS-025 or INS-027) beside the
  // question: fieldseal.problems([{path, message}]) replaces what it showed before.
  window.fieldseal = {
    problems: function (list) {
      Array.prototype.forEach.call(doc.querySelectorAll(".q[data-bind]"), function (q) {
        if (q.fsCore) { q.fsCore = false; refreshQuestion(q); }
      });
      (list || []).forEach(function (p) {
        var path = String(p.path || "").replace(/\.unit$/, "");
        var q = doc.querySelector('.q[data-bind="' + path.replace(/["\\]/g, "\\$&") + '"]');
        if (!q) return;
        q.fsCore = true;
        q.fsMsg = String(p.message || "");
        (q.matches("fieldset") ? q : q.querySelector("input, textarea") || q).setAttribute("aria-invalid", "true");
        showMessage(q);
      });
    }
  };

  // Paging (WEB-184, Hick's law): a category's foods are shown a few at a time, never as one long
  // scroll. Two per page on wide windows, one on compact ones.
  var perPage = doc.body.classList.contains("wc-compact") ? 1 : 2;
  function pageList(list) {
    var items = Array.prototype.slice.call(list.querySelector(".instances").children);
    if (items.length <= perPage) return;
    var pages = Math.ceil(items.length / perPage);
    var title = (list.querySelector(".box-head .box-title") || {}).textContent || "";
    var nav = doc.createElement("nav");
    nav.className = "pager";
    nav.setAttribute("aria-label", "Pages of " + title);
    nav.innerHTML = '<button type="button" class="btn pager-prev" aria-label="Previous page">←</button>' +
      '<span class="pager-at" aria-live="polite"></span>' +
      '<button type="button" class="btn pager-next" aria-label="Next page">→</button>';
    list.querySelector(".box-head").appendChild(nav);
    var at = 0;
    function go(i) {
      at = Math.max(0, Math.min(pages - 1, i));
      // Its own marker, not `hidden`: rule evaluation sets `hidden` on nodes and must not undo paging.
      items.forEach(function (it, k) { it.toggleAttribute("data-off-page", Math.floor(k / perPage) !== at); });
      nav.querySelector(".pager-at").textContent = title + " · " + (at + 1) + " of " + pages;
      nav.querySelector(".pager-prev").disabled = at === 0;
      nav.querySelector(".pager-next").disabled = at === pages - 1;
    }
    nav.querySelector(".pager-prev").addEventListener("click", function () { go(at - 1); });
    nav.querySelector(".pager-next").addEventListener("click", function () { go(at + 1); });
    go(0);
  }
  Array.prototype.forEach.call(doc.querySelectorAll(".list"), function (l) { if (l.querySelector(".instances")) pageList(l); });

  // The navigation rail (WEB-185): every step, and under the current one its categories, each
  // with its progress. Collapsible; on compact windows a drawer opened from the top bar.
  function answered(q) {
    if (q.querySelector("input:checked")) return true;
    if (q.querySelector('.nr-btn[aria-pressed="true"]')) return true;
    return Array.prototype.some.call(q.querySelectorAll("input[type=number], input[type=text], input[type=date], textarea, select"), function (c) { return c.value !== ""; });
  }
  function progress(scope) {
    var qs = Array.prototype.filter.call(scope.querySelectorAll(".q"), function (q) { return !q.closest("[hidden]") || scope.contains(q); });
    var done = qs.filter(answered).length;
    return { done: done, total: qs.length, state: done === 0 ? "todo" : done === qs.length ? "done" : "part" };
  }
  var stepLinks = Array.prototype.slice.call(doc.querySelectorAll(".stepper a"));
  var stepEls = Array.prototype.slice.call(doc.querySelectorAll("section.step"));
  if (stepLinks.length) {
    var rail = doc.createElement("nav");
    rail.className = "rail";
    rail.setAttribute("aria-label", "Survey outline");
    var toggle = doc.createElement("button");
    toggle.type = "button";
    toggle.className = "rail-toggle";
    toggle.setAttribute("aria-expanded", "true");
    toggle.innerHTML = '<span aria-hidden="true">☰</span><span class="rail-label">Outline</span>';
    var listEl = doc.createElement("ol");
    rail.appendChild(toggle);
    rail.appendChild(listEl);
    doc.body.appendChild(rail);
    doc.body.classList.add("has-rail");
    var compact = doc.body.classList.contains("wc-compact");
    function setOpen(open) {
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      doc.body.classList.toggle("rail-closed", !open);
    }
    setOpen(!compact);
    toggle.addEventListener("click", function () { setOpen(toggle.getAttribute("aria-expanded") !== "true"); });
    function render() {
      listEl.innerHTML = "";
      stepLinks.forEach(function (a, j) {
        var li = doc.createElement("li");
        var current = !stepEls[j].hidden;
        var p = progress(stepEls[j]);
        var b = doc.createElement("button");
        b.type = "button";
        b.className = "rail-item rail-step is-" + p.state;
        if (current) b.setAttribute("aria-current", "step");
        b.innerHTML = '<span class="rail-dot" aria-hidden="true"></span><span class="rail-text"></span><span class="rail-count"></span>';
        b.querySelector(".rail-text").textContent = a.textContent.replace(/^\s*\d+\.\s*/, "");
        b.querySelector(".rail-count").textContent = p.done + "/" + p.total;
        b.addEventListener("click", function () { a.click(); if (compact) setOpen(false); render(); });
        li.appendChild(b);
        var tabs = current ? Array.prototype.slice.call(stepEls[j].querySelectorAll("[role=tab]")) : [];
        if (tabs.length) {
          var sub = doc.createElement("ol");
          tabs.forEach(function (t) {
            var panel = doc.getElementById(t.getAttribute("aria-controls"));
            var tp = panel ? progress(panel) : { done: 0, total: 0, state: "todo" };
            var c = doc.createElement("button");
            c.type = "button";
            c.className = "rail-item rail-cat is-" + tp.state;
            if (t.getAttribute("aria-selected") === "true") c.setAttribute("aria-current", "true");
            c.innerHTML = '<span class="rail-text"></span><span class="rail-count"></span>';
            c.querySelector(".rail-text").textContent = t.textContent;
            c.querySelector(".rail-count").textContent = tp.done + "/" + tp.total;
            c.addEventListener("click", function () { t.click(); if (compact) setOpen(false); render(); });
            var li2 = doc.createElement("li");
            li2.appendChild(c);
            sub.appendChild(li2);
          });
          li.appendChild(sub);
        }
        listEl.appendChild(li);
      });
    }
    render();
    doc.addEventListener("change", render);
    doc.addEventListener("click", function (e) { if (e.target.closest(".step-nav, .stepper, [role=tab]")) setTimeout(render, 0); });
  }
})();
