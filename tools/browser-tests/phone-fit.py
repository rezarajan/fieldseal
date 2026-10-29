#!/usr/bin/env python3
"""The browser device on a phone: no screen needs scrolling (issue #47).

For each example survey, a device is registered as a collector would (a token from the factory
portal, the four words confirmed), takes its bundle, and is then used in a 390 x 844 window: the
list of surveys, the roster, the consent screen when there is one, every step of the form in its
compact layout (INS-210), and the review. On each screen the check is that the page does not
scroll, nothing inside the screen is cut off or scrolls (the form is checked inside its frame),
and the primary action is fully in view and not covered. Only the lists of people, of surveys
and of answers (#subjects, #survey-list, .review-list) may scroll inside themselves (WEB-189):
a list longer than a screen has to. The test also fills each of them past a screen's height to
show that the screen still fits and its primary action stays in view, and it injects a tall
element into a screen to show that the check fails when page content overflows.

    phone-fit.py [--collector URL] [--factory URL] [--state DIR]

Run against a running `just web` that has assigned `household-water-access` to the presenter and
`school-meals-baseline` to collector1 (`tools/dev-web.sh --check --browser` does). Exit 0 only when
every check passes.
"""
import asyncio
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
spec = importlib.util.spec_from_file_location("demo_e2e", os.path.join(HERE, "demo-e2e.py"))
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)  # the shared browser driver and portal helpers; it runs nothing

WIDTH, HEIGHT = 390, 844
# The lists that may scroll within themselves; nothing else on a screen may.
SCROLLABLE = "#subjects, #survey-list, .review-list"
SURVEYS = [("presenter", "household-water-access"), ("collector1", "school-meals-baseline")]

# What a screen's measurements say, read in the page: the page itself, every element of the device
# (and its ancestors) that cuts its content off or scrolls, except the lists that may, the primary
# actions in view, and the form.
MEASURE = """(() => {
  const out = { size: [innerWidth, innerHeight], page: document.scrollingElement.scrollHeight - innerHeight, cut: [], primary: [], below: [], frame: null };
  const screens = [...document.querySelectorAll('#device section[data-step]:not([hidden]) [data-screen]:not([hidden])')];
  const name = (e) => (e.id ? '#' + e.id : e.tagName.toLowerCase() + (e.className && typeof e.className === 'string' ? '.' + e.className.split(' ')[0] : ''));
  const watched = new Set(['html', 'body', 'main', '#device']);
  for (const root of [document.body, ...screens]) {
    for (const e of [root, ...root.querySelectorAll('*')]) {
      if (e.closest('.visually-hidden, [hidden], details:not([open]) > :not(summary), iframe')) continue;
      if (e.matches('__SCROLLABLE__')) continue;
      const css = getComputedStyle(e);
      if (css.display === 'none' || !e.getClientRects().length) continue;
      const clips = ['auto', 'scroll', 'hidden'].includes(css.overflowY);
      if (clips && e.scrollHeight > e.clientHeight + 1 && !(e === document.body && css.overflowY === 'visible')) {
        out.cut.push(name(e) + ' ' + e.scrollHeight + '>' + e.clientHeight);
      }
    }
  }
  // Whatever is drawn below the window is something to scroll to, whatever clips it: nothing outside
  // the lists that may scroll can be there.
  for (const e of document.body.querySelectorAll('*')) {
    if (e.closest('.visually-hidden, [hidden], details:not([open]) > :not(summary), iframe, __SCROLLABLE__, script, style')) continue;
    if (!e.getClientRects().length) continue;
    const r = e.getBoundingClientRect();
    if (r.height > 0 && r.bottom > innerHeight + 1) out.below.push(name(e) + ' ' + Math.round(r.bottom));
  }
  // The screen's ancestors too: one that clips what the screen overflows hides it from the page's own height.
  for (const screen of screens) {
    for (let e = screen.parentElement; e; e = e.parentElement) {
      const css = getComputedStyle(e);
      if (['auto', 'scroll', 'hidden'].includes(css.overflowY) && e.scrollHeight > e.clientHeight + 1) out.cut.push(name(e) + ' ' + e.scrollHeight + '>' + e.clientHeight);
    }
  }
  for (const b of document.querySelectorAll('#device .btn-primary')) {
    if (!b.getClientRects().length || b.closest('[hidden]')) continue;
    const r = b.getBoundingClientRect();
    if (!b.closest('section[data-step]:not([hidden])')) continue;
    // In view means all of the button is inside the window, and the button, not something over it,
    // is what a finger would touch at its centre.
    const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    out.primary.push([name(b), Math.round(r.top), Math.round(r.bottom), Math.round(r.left), Math.round(r.right), !!at && b.contains(at)]);
  }
  const f = document.getElementById('frame');
  if (f && f.getClientRects().length && f.contentDocument && f.contentDocument.scrollingElement) {
    const d = f.contentDocument.scrollingElement;
    out.frame = { width: f.clientWidth, height: f.clientHeight, content: d.scrollHeight, over: d.scrollHeight - f.clientHeight };
  }
  return out;
})()""".replace("__SCROLLABLE__", SCROLLABLE)


def verdict(m):
    """Whether the measurements of a screen are those of one that fits a phone."""
    in_view = all(0 <= top and bottom <= HEIGHT and 0 <= left and right <= WIDTH and hit for _, top, bottom, left, right, hit in m["primary"])
    return bool(m["size"] == [WIDTH, HEIGHT] and m["page"] <= 0 and not m["cut"] and not m["below"] and m["primary"] and in_view and (m["frame"] is None or m["frame"]["over"] <= 1))


async def fits(device, what):
    """Checks that the screen on show needs no scrolling; returns its measurements."""
    m = await device.ev(MEASURE)
    ok = verdict(m)
    e2e.check(ok, f"phone: {what} fits {WIDTH}x{HEIGHT} without scrolling", json.dumps(m) if not ok else "")
    return m


# A list gets 12 more rows, copies of one it shows (or one made here), which is what a longer list
# of people, surveys or answers looks like to the layout. Returns how tall the list is and how
# tall its own area is. The copies are marked so that they can be taken away again.
FILL = """((host, rows, scroller) => {
  const box = document.querySelector(host);
  let first = [...box.querySelectorAll(rows)].find((r) => r.getClientRects().length);
  if (!first) {
    first = document.createElement('div');
    first.className = rows.replace(/^\\./, '');
    first.innerHTML = '<span class="lbl">Question</span><span class="val">Answer</span>';
    box.append(first);
    first.dataset.copy = '1';
  }
  for (let i = 0; i < 12; i++) {
    const c = first.cloneNode(true);
    c.dataset.copy = '1';
    box.append(c);
  }
  const area = document.querySelector(scroller);
  return [area.scrollHeight, area.clientHeight];
})"""


async def long_list(device, what, host, rows, scroller, list_name):
    """Fills a list past the height of the screen: the list must scroll in itself, and the screen must still fit with its primary action in view."""
    total, shown = await device.ev(f"{FILL}({json.dumps(host)}, {json.dumps(rows)}, {json.dumps(scroller)})")
    e2e.check(total > shown, f"phone: the long {list_name} is taller than its own area and scrolls inside it", f"{total} <= {shown}")
    await asyncio.sleep(0.2)
    m = await fits(device, f"{what} with a long {list_name}")
    e2e.check(bool(m["primary"]) and all(top >= 0 and bottom <= HEIGHT for _, top, bottom, *_ in m["primary"]), f"phone: the primary action of {what} stays in view with a long {list_name}", json.dumps(m["primary"]))
    await device.ev("document.querySelectorAll('[data-copy]').forEach((e) => e.remove())")
    await asyncio.sleep(0.2)


async def must_not_fit(device, what):
    """The check itself: content that overflows the screen makes it fail."""
    await device.ev("""(() => {
      const screen = document.querySelector('#device section[data-step]:not([hidden]) [data-screen]:not([hidden])');
      const tall = document.createElement('div');
      tall.id = 'injected-tall';
      tall.style.cssText = 'flex:none;height:%dpx;background:#ccc';
      screen.append(tall);
    })()""" % (HEIGHT * 2))
    await asyncio.sleep(0.2)
    m = await device.ev(MEASURE)
    where = await device.ev("""(() => { const t = document.getElementById('injected-tall'); const r = t.getBoundingClientRect(); const p = t.parentElement; const cs = getComputedStyle(p); return JSON.stringify({ tall: [r.top, r.height], parent: [p.id || p.className, p.clientHeight, p.scrollHeight, cs.display, cs.overflowY], body: [document.body.scrollHeight, innerHeight] }); })()""")
    e2e.check(not verdict(m), f"phone: the check fails when content overflows {what}", (json.dumps(m) + where) if verdict(m) else "")
    await device.ev("document.getElementById('injected-tall').remove()")
    await asyncio.sleep(0.2)


async def screen(device, name, seconds=60):
    await e2e.until_async(lambda: device.ev(f"document.getElementById('device').dataset.screen === {json.dumps(name)}"), f"screen {name}", seconds)
    await asyncio.sleep(0.4)


# Answers the first choice of the form's visible step with its first option, so the review has a row
# or two (the review of a whole survey scrolls inside its own list, which is not what is measured).
ANSWER = """(async () => {
  const doc = document.getElementById('frame').contentDocument;
  const step = [...doc.querySelectorAll('.step')].find((s) => !s.hidden) || doc.body;
  for (const q of step.querySelectorAll('fieldset[data-control=choice], fieldset[data-control=yes-no], fieldset[data-control=scale]')) {
    if (q.style.display === 'none' || q.hidden || !q.getClientRects().length) continue;
    const r = q.querySelector('input[type=radio]');
    if (r && !q.querySelector('input:checked')) { r.click(); break; }
  }
  await new Promise((r) => setTimeout(r, 350));
})()"""

# What a linear step needs before "Next" works: every visible question that is empty gets an
# answer (the first option of a choice, the lowest number, a word).
ANSWER_ALL = """(async () => {
  const doc = document.getElementById('frame').contentDocument;
  const step = [...doc.querySelectorAll('.step')].find((s) => !s.hidden) || doc.body;
  const fire = (e) => { for (const t of ['input', 'change']) e.dispatchEvent(new Event(t, { bubbles: true })); };
  for (const q of step.querySelectorAll('[data-bind]')) {
    if (q.style.display === 'none' || q.hidden || !q.getClientRects().length) continue;
    const radios = [...q.querySelectorAll('input[type=radio]')];
    if (radios.length) { if (!radios.some((r) => r.checked)) radios[0].click(); continue; }
    for (const i of q.querySelectorAll('input[type=number]')) if (i.value === '' && !i.disabled) { i.value = i.min || '1'; fire(i); }
    for (const i of q.querySelectorAll('input[type=text], textarea')) if (i.value === '' && !i.disabled) { i.value = 'x'; fire(i); }
  }
  await new Promise((r) => setTimeout(r, 450));
})()"""

NEXT = """(() => {
  const doc = document.getElementById('frame').contentDocument;
  const n = [...doc.querySelectorAll('.step-nav .next, button, a')].find((e) => /^\\s*Next/.test(e.textContent) && !e.disabled && e.getClientRects().length);
  if (!n) return false;
  n.click();
  return true;
})()"""

BACK = NEXT.replace("^\\s*Next", "Back")

STUCK = """(() => {
  const d = document.getElementById('frame').contentDocument;
  const st = [...d.querySelectorAll('.step')].find((s) => !s.hidden);
  return JSON.stringify({
    nav: [...d.querySelectorAll('.step-nav button, .step-nav a')].filter((e) => e.getClientRects().length).map((e) => [e.textContent.trim(), e.disabled, e.getAttribute('aria-disabled')]),
    questions: [...st.querySelectorAll('[data-bind]')].map((q) => [q.dataset.bind, q.className, q.style.display, q.querySelectorAll('input:checked').length, q.querySelector('input') ? q.querySelector('input').disabled : null]),
    verdicts: document.getElementById('verdicts').textContent.slice(0, 200),
  });
})()"""

STEP_TITLE = "(() => { const d = document.getElementById('frame').contentDocument; const t = d.querySelector('.step:not([hidden]) .step-title') || d.querySelector('.stepper a[aria-current=step]'); return t ? t.textContent.trim().replace(/\\s+/g, ' ') : ''; })()"


async def register_device(browser, login, instrument):
    """Registers a device for `login` in a phone-sized window, as the guided demo does, and returns the portal tab and the device tab, which waits for the surveys."""
    e2e.LOGIN = login
    portal = await browser.tab()
    device = await browser.tab()
    await device.send("Emulation.setDeviceMetricsOverride", width=WIDTH, height=HEIGHT, deviceScaleFactor=1, mobile=False)

    # Register a device for this account, as the guided demo does.
    await e2e.sign_in(portal, e2e.FACTORY)
    html = await e2e.portal_html(portal)
    for tenancy in re.findall(r'action="/devices/([^"/]*)/retire"', html):
        await e2e.portal_post(portal, f"/devices/{tenancy}/retire")
    await portal.goto(e2e.FACTORY + "/", 0.5)
    r = await e2e.portal_post(portal, "/tokens", {"route": "online"})
    token = (re.search(r'<p class="token">([^<]+)</p>', r["text"]) or [None, ""])[1]
    e2e.check(token.startswith("FS1T:"), "the portal issues a registration token")
    await device.goto(e2e.COLLECTOR + "/device", 2.0)
    await device.ev(open(os.path.join(HERE, "device-flow.js")).read() + ";1")
    await device.ev(f"window.INSTRUMENT={json.dumps(instrument)};window.TOKEN={json.dumps(token)};1")
    for name in ("starts", "pin", "register"):
        await device.ev(f"window.flowStep({json.dumps(name)})")
    tenancy = await device.ev("window.__tenancy")
    await e2e.portal_post(portal, f"/pending/{tenancy}/confirm")
    await device.ev("window.flowStep('registered')")
    return portal, device


async def retire_devices(portal):
    """Leaves the factory as it was found."""
    html = await e2e.portal_html(portal)
    for t in re.findall(r'action="/devices/([^"/]*)/retire"', html):
        await e2e.portal_post(portal, f"/devices/{t}/retire")


async def one(browser, login, instrument):
    e2e.section(f"phone: {instrument} (account {login})")
    portal, device = await register_device(browser, login, instrument)

    # The surveys the account is assigned, then the roster of the one chosen.
    await screen(device, "surveys", 120)
    await fits(device, "your surveys")
    await must_not_fit(device, "your surveys")
    await long_list(device, "your surveys", "#survey-list", ".subject", "#survey-list", "list of surveys")
    await device.ev("document.getElementById('open-survey').click()")
    await screen(device, "roster")
    await fits(device, "the roster")
    await long_list(device, "the roster", "#subjects", ".subject", "#subjects", "roster of people")

    # A capture: consent first when the survey asks for it, then each step of the form.
    await device.ev("document.getElementById('start-next').click()")
    await e2e.until_async(lambda: device.ev("['consent','capture'].includes(document.getElementById('device').dataset.screen)"), "consent or capture")
    if await device.ev("document.getElementById('device').dataset.screen") == "consent":
        await asyncio.sleep(0.3)
        await fits(device, "the consent screen")
        await device.ev("document.querySelector('#consent-basis input').click();document.getElementById('form-consent').requestSubmit()")
    await screen(device, "capture")
    await e2e.until_async(lambda: device.ev("(() => { const d = document.getElementById('frame').contentDocument; return !!(d && d.querySelector('.step')); })()"), "the form")
    await asyncio.sleep(0.8)
    width = await device.ev("document.getElementById('frame').clientWidth")
    e2e.check(width < 600, "phone: the form is drawn in its compact layout", width)

    steps = 0
    seen = set()
    while steps < 60:
        steps += 1
        title = await device.ev(STEP_TITLE)
        seen.add(title)
        await fits(device, f"capture step {steps} ({title})")
        if steps <= 2:
            await device.ev(ANSWER)
        if re.search(r"Step (\d+) of \1(?!\d)", title):
            break  # the last step
        if not await device.ev(NEXT):
            await device.ev(ANSWER_ALL)
            if not await device.ev(NEXT):
                # A question of an earlier step decides whether this one applies: answer that first.
                await device.ev(BACK)
                await asyncio.sleep(0.4)
                await device.ev(ANSWER_ALL)
                await device.ev(NEXT)
                await asyncio.sleep(0.4)
                await device.ev(ANSWER_ALL)
                if not await device.ev(NEXT):
                    print("  stuck on", title, await device.ev(STUCK))
                    break
        await asyncio.sleep(0.4)
    e2e.check(steps > 2 and len(seen) > 2, f"phone: the compact layout of {instrument} has several short steps", f"{steps} steps: {sorted(seen)}")
    e2e.check(bool(re.search(r"Step (\d+) of \1(?!\d)", title)), f"phone: every step of {instrument} was visited, to the last", title)

    # The review of what was answered.
    await e2e.until_async(lambda: device.ev("!document.getElementById('to-review').disabled"), "the review button", 30)
    await device.ev("document.getElementById('to-review').click()")
    await screen(device, "review")
    await fits(device, "the review")
    await long_list(device, "the review", "#review-out", ".row", ".review-list", "list of answers")

    if device.errors:
        print("  page errors:", device.errors[:3])
    await retire_devices(portal)


async def main():
    browsers = []
    try:
        for login, instrument in SURVEYS:
            # A browser for each account: its own cookies and its own device storage.
            browser = e2e.Browser()
            await browser.start()
            browsers.append(browser)
            await one(browser, login, instrument)
    finally:
        for b in browsers:
            b.proc.kill()
    print("\nRESULT", f"FAILED: {len(e2e.failures)} check(s): " + "; ".join(e2e.failures) if e2e.failures else "every device screen fits a phone without scrolling")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
