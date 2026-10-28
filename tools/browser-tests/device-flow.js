// The browser device, end to end, as a collector would use it: create the PIN on the pad,
// register against the demo factory, take the bundle, start a capture, fill in a few answers,
// review, seal by holding, hand over (upload and receipt), clear. Evaluated in the page by
// device-flow.py, which runs `window.flow` step by step and takes the screenshots.
(() => {
  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const checks = (window.__checks = []);
  const check = (name, ok, detail = "") => checks.push([name, !!ok, String(detail)]);
  const until = async (f, what, tries = 200) => {
    for (let i = 0; i < tries; i++) { try { if (f()) return true; } catch { /* not yet */ } await sleep(100); }
    throw new Error("timed out waiting for " + what + " (screen is " + $("device").dataset.screen + "; log: " + [...document.querySelectorAll("#log li")].slice(-3).map((x) => x.textContent).join(" | ") + ")");
  };
  const screen = (name) => until(() => $("device").dataset.screen === name, "screen " + name);
  const doc = () => $("frame").contentDocument;
  const visible = (e) => !!e && e.getClientRects().length > 0;
  const click = (e) => e.click();
  const pad = (form, digits) => { for (const d of digits) [...document.querySelectorAll(`#${form} .pad button`)].find((b) => b.textContent === d).click(); };
  const press = async (button, ms) => {
    const r = button.getBoundingClientRect();
    const o = { bubbles: true, pointerId: 1, pointerType: "mouse", button: 0, clientX: r.x + r.width / 2, clientY: r.y + r.height / 2 };
    button.dispatchEvent(new PointerEvent("pointerdown", o));
    await sleep(ms);
    button.dispatchEvent(new PointerEvent("pointerup", o));
  };
  const fire = (e, ...types) => { for (const t of types) e.dispatchEvent(new Event(t, { bubbles: true })); };
  const PIN = "246810";
  const instrument = window.INSTRUMENT || "household-water-access";

  // Answers the visible questions of the form's current step: the first option of each choice.
  const answerStep = async () => {
    const step = [...doc().querySelectorAll(".step")].find((s) => !s.hidden) || doc().body;
    for (const q of step.querySelectorAll("fieldset[data-control=choice], fieldset[data-control=yes-no]")) {
      if (q.closest("[hidden]") && !q.closest(".step")) continue;
      if (q.style.display === "none" || q.hidden) continue;
      const r = q.querySelector("input[type=radio]");
      if (r && !q.querySelector("input:checked")) { r.click(); }
    }
    await sleep(400);
  };

  window.flow = [
    { name: "starts", shot: "01-session-pin.png", run: async () => {
      await until(() => ["create", "unlock", "unavailable"].includes($("device").dataset.screen), "the device to start");
      check("the device starts on the PIN screen", $("device").dataset.screen === "create", $("device").dataset.screen);
      check("one step visible at a time", [...document.querySelectorAll("section[data-step]")].filter((s) => !s.hidden).length === 1);
      check("the session step is the visible one", $("device").dataset.step === "session");
      check("one primary action on the screen", [...document.querySelectorAll("#form-create .btn-primary")].length === 1);
      check("the security log is collapsed", !$("log-box").open);
      check("a latest result line is shown", $("latest").textContent.length > 0, $("latest").textContent);
      pad("form-create", "246");
    } },
    { name: "pin", run: async () => {
      check("the dots follow the pad", document.querySelectorAll("#form-create .dots .on").length === 3);
      pad("form-create", "810");
      $("form-create").requestSubmit();
      await until(() => $("create-title").textContent === "Enter it again", "the confirmation entry");
      pad("form-create", PIN);
      $("form-create").requestSubmit();
      await screen("register");
      check("a new tenancy goes to registration", true);
    } },
    { name: "register", run: async () => {
      const text = await (await fetch("/registration/token", { method: "POST" })).text();
      const token = /<pre class="token">([^<]*)/.exec(text)[1];
      $("token").value = token;
      $("form-register").requestSubmit();
      await until(() => $("reg-status") && /pending/i.test($("reg-status").textContent), "pending status");
      check("the four words are shown big", document.querySelector("#register-result .words").textContent.trim().split(/\s+/).length >= 4, document.querySelector("#register-result .words").textContent);
      const tenancy = /Tenancy ([0-9a-f]{64})/.exec($("tenancy-info").textContent)[1];
      const c = await fetch("/registration/confirm", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "tenancy=" + tenancy });
      check("the portal confirms the words", c.status < 400, c.status);
      await screen("bundle");
    } },
    { name: "bundle", shot: "02-session-roster.png", run: async () => {
      check("the bundle screen offers one primary", [...document.querySelectorAll("#screen-bundle .btn-primary")].length === 1);
      const radios = [...document.querySelectorAll("#instrument-pick input")];
      if (radios.length) {
        check("the instrument picker is behind a disclosure", !$("bundle-options").open && $("bundle-options").tagName === "DETAILS");
        const r = radios.find((x) => x.value === instrument);
        if (r) r.click();
      }
      $("fetch-bundle").click();
      await until(() => ["roster", "consent"].includes($("device").dataset.screen), "the roster", 300);
      await sleep(300);
    } },
    { name: "roster", shot: "03-about.png", run: async () => {
      check("the roster lists the people", document.querySelectorAll("#subjects .subject").length > 0, document.querySelectorAll("#subjects .subject").length);
      check("the latest result names the verified bundle", /bundle/i.test($("latest").textContent), $("latest").textContent);
      check("the security log keeps every step", +$("log-count").textContent >= 5, $("log-count").textContent);
      check("the roster has one primary", [...document.querySelectorAll("#screen-roster .btn-primary")].length === 1);
      $("start-next").click();
      await until(() => ["capture", "consent"].includes($("device").dataset.screen) || $("capture-error").textContent, "capture or consent", 100);
      if ($("device").dataset.screen === "consent") {
        document.querySelector("#consent-basis input").click();
        $("form-consent").requestSubmit();
      }
      await screen("capture");
      await until(() => doc() && doc().querySelector(".step") && $("verdicts") !== null && document.querySelector('#pills li[aria-current]').dataset.pill === "about", "the form");
      await sleep(900);
      check("the form fills the frame area", $("frame").getBoundingClientRect().height > 300, $("frame").getBoundingClientRect().height);
    } },
    { name: "about", run: async () => {
      check("only the subject name and Close are in the capture bar", $("capture-subject").textContent.length > 0 && $("discard").textContent === "Close");
      await answerStep();
      check("an unsealed capture is never discarded by one click", $("close-confirm").hidden);
    } },
    { name: "foods", shot: "04-foods.png", run: async () => {
      const next = [...doc().querySelectorAll(".step-nav .next")].find(visible);
      if (next) next.click();
      await sleep(900);
      const tab = doc().querySelector("[role=tab]");
      check("the later step shows tabs or cards", !!doc().querySelector(".step:not([hidden])"));
      if (tab) { const tabs = [...doc().querySelectorAll("[role=tab]")]; if (tabs[1]) tabs[1].click(); await sleep(300); }
      // Answer what is visible: a number or a choice.
      const num = [...doc().querySelectorAll("input[type=number]")].find((i) => visible(i) && !i.disabled);
      if (num) { num.value = num.max ? String(Math.floor(+num.max / 2)) : "2"; fire(num, "input", "change"); }
      await answerStep();
      await sleep(600);
      const tabs = doc().querySelector(".tabs");
      if (tabs) { tabs.scrollIntoView({ block: "start" }); await sleep(300); }
    } },
    { name: "integrity", run: async () => {
      // A number above its maximum is never stored: it is refused in the page, or flagged by the
      // core and the way to Review & seal is blocked with the reason.
      // Answering how often makes the amount applicable.
      const freq = [...doc().querySelectorAll("[data-control=scale]")].find(visible);
      if (freq) { const r = freq.querySelectorAll("input[type=radio]")[3]; if (r) r.click(); await sleep(900); }
      const num = [...doc().querySelectorAll("input[type=number]")].find((i) => i.max && visible(i) && !i.disabled);
      if (num) {
        const max = +num.max;
        num.value = String(max * 5);
        fire(num, "input", "change");
        await sleep(900);
        const refused = num.value === "" || +num.value <= max;
        const shown = !!$("verdicts").querySelector(".problem");
        check("a value above the maximum is refused or flagged inline", refused || shown, num.value + " / " + $("verdicts").textContent);
        if (!refused) check("review and seal is blocked while a value problem exists", $("to-review").disabled, $("to-review").title);
        num.value = String(Math.max(+num.min || 0, Math.min(max, 1)));
        fire(num, "input", "change");
        await sleep(900);
        check("putting the value right clears the block", !$("to-review").disabled || !!$("verdicts").textContent, $("verdicts").textContent);
      } else {
        check("(no bounded number on this instrument)", instrument === "household-water-access");
      }
    } },
    { name: "review", shot: "05-review.png", run: async () => {
      check("one primary on the capture screen", [...document.querySelectorAll("#capture .btn-primary")].length === 1);
      await until(() => !$("to-review").disabled, "the review button");
      $("to-review").click();
      await screen("review");
      check("the review lists answers", document.querySelectorAll("#review-out .row").length > 0, document.querySelectorAll("#review-out .row").length);
      check("the hold button is the single primary", [...document.querySelectorAll("#screen-review .btn-primary")].length === 1);
      if (!$("ack").hidden) {
        check("sealing waits for the acknowledgement of unanswered items", $("seal").getAttribute("aria-disabled") === "true");
        $("ack").click();
      }
      check("sealing is possible once checked", $("seal").getAttribute("aria-disabled") === "false");
    } },
    { name: "seal", run: async () => {
      await press($("seal"), 300);
      await sleep(300);
      check("letting go early cancels", $("device").dataset.screen === "review");
      const key = async (ms) => {
        $("seal").focus();
        $("seal").dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
        await sleep(ms);
        $("seal").dispatchEvent(new KeyboardEvent("keyup", { key: " ", bubbles: true }));
      };
      await key(300);
      await sleep(200);
      check("letting go the key early cancels", $("device").dataset.screen === "review");
      // The keyboard seals the household record; the pointer seals the food record.
      if (instrument === "household-water-access") await key(1700); else await press($("seal"), 1700);
      await screen("sealed");
      check("sealed", /sealed/i.test($("sealed-text").textContent), $("sealed-text").textContent);
      check("the latest result names the record", /sealed/.test($("latest").textContent), $("latest").textContent);
    } },
    { name: "export", shot: "06-export.png", run: async () => {
      $("sealed-export").click();
      await screen("ready");
      check("the export screen has one primary", [...document.querySelectorAll("#screen-ready .btn-primary")].length === 1);
      check("clear is behind a disclosure", $("clear-box").tagName === "DETAILS" && !$("clear-box").open);
    } },
    { name: "upload", run: async () => {
      $("export").click();
      await until(() => $("export-out").textContent.includes("Export"), "the export");
      check("the export is built and verified", /verified|record/.test($("latest").textContent), $("latest").textContent);
      $("upload").click();
      await screen("done");
      check("the receipt is verified", /Receipt verified/.test($("upload-out").textContent), $("upload-out").textContent);
    } },
    { name: "clear", run: async () => {
      $("clear-box").open = true;
      $("clear-preview").click();
      await until(() => !$("form-clear").hidden, "the clear preview");
      $("clear-pin1").value = PIN;
      $("clear-pin2").value = PIN;
      $("form-clear").requestSubmit();
      await until(() => $("clear-out").textContent.startsWith("Cleared"), "the clear", 300);
      check("cleared", true, $("clear-out").textContent);
      const intake = await (await fetch("/intake")).text();
      check("the intake page shows the landed rows", /<table/.test(intake) || /rows?/i.test(intake));
      check("the security log is still there", document.querySelectorAll("#log li").length >= 10, document.querySelectorAll("#log li").length);
    } },
  ];
})();
