#!/usr/bin/env python3
"""Browser-level test of the HTML adapter's constraint enforcement (INS-025, INS-027, INS-133).

Opens rendered instrument pages in headless Chromium over the DevTools protocol and drives
them like a collector:

  food page   - question 11a (multi-choice, max 4): a fifth option cannot be ticked, the count
                reads "4 of 4 chosen", unticking frees the rest; keyboard works; "amount eaten
                each time" (stepper, 0.5..20): typed 100 is refused, "+" stops at 20; money
                typed above its maximum is flagged and has no canonical value.
  water page  - an exclusive option clears the others and is cleared by them (INS-133); a
                small bounded whole number is a - / value / + stepper that stops at its bounds.

Usage (chromium and python3 with `websockets` on the PATH, see crates/apps/web/tests/
browser_constraints.rs for the nix invocation):

    constraints.py FOOD.html WATER.html

Exits 0 when every check passes, 1 otherwise.
"""
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import websockets

FAILED = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok or not detail else "  -> " + str(detail)))
    if not ok:
        FAILED.append(name)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Browser:
    def __init__(self):
        self.port = free_port()
        self.profile = tempfile.mkdtemp(prefix="fieldseal-chrome-")
        self.proc = subprocess.Popen(
            [
                "chromium", "--headless=new", "--no-sandbox", "--disable-gpu",
                f"--remote-debugging-port={self.port}", f"--user-data-dir={self.profile}",
                "--window-size=1280,2000", "about:blank",
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.n = 0
        self.ws = None
        self.errors = []

    async def start(self):
        tabs = None
        for _ in range(120):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json"))
                if any(t["type"] == "page" for t in tabs):
                    break
            except Exception:
                pass
            await asyncio.sleep(0.5)
        url = [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        self.ws = await websockets.connect(url, max_size=None)
        await self.send("Runtime.enable")
        await self.send("Page.enable")

    async def send(self, method, **params):
        self.n += 1
        i = self.n
        await self.ws.send(json.dumps({"id": i, "method": method, "params": params}))
        while True:
            m = json.loads(await self.ws.recv())
            if m.get("method") == "Runtime.exceptionThrown":
                self.errors.append(json.dumps(m["params"]["exceptionDetails"].get("exception", m["params"]["exceptionDetails"]))[:400])
            if m.get("id") == i:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})

    async def ev(self, js):
        r = await self.send("Runtime.evaluate", expression=js, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in r:
            raise RuntimeError(json.dumps(r["exceptionDetails"])[:400])
        return r["result"].get("value")

    async def open(self, path, find_step_js=None):
        """Loads the page; when `find_step_js` (an expression for an element) is given, opens
        the step that holds it, as a `#step-N` link does."""
        url = "file://" + os.path.abspath(path)
        await self.send("Page.navigate", url="about:blank")
        await self.send("Page.navigate", url=url)
        await asyncio.sleep(0.8)
        if find_step_js:
            k = await self.ev(f"(function(){{var e={find_step_js};var s=e&&e.closest('.step');return s?s.getAttribute('data-step'):null}})()")
            if k is not None:
                await self.send("Page.navigate", url="about:blank")
                await self.send("Page.navigate", url=f"{url}#step-{k}")
                await asyncio.sleep(0.8)

    async def type_text(self, selector, text):
        await self.ev(f"document.querySelector({json.dumps(selector)}).focus()")
        await self.send("Input.insertText", text=text)

    async def key(self, key, code, vk, text=None):
        base = dict(key=key, code=code, windowsVirtualKeyCode=vk)
        await self.send("Input.dispatchKeyEvent", type="keyDown", **base, **({"text": text} if text else {}))
        await self.send("Input.dispatchKeyEvent", type="keyUp", **base)

    def close(self):
        try:
            self.proc.terminate()
        except Exception:
            pass


# The question element that binds `path` ends with.
def q_of(suffix):
    return f"[...document.querySelectorAll('.q[data-bind]')].find(q=>q.dataset.bind.endsWith({json.dumps(suffix)}))"


async def food(b, path):
    # ---- 11a: multi-choice, max 4 -------------------------------------------------------
    q = q_of("money_buys")
    await b.open(path, q)
    info = await b.ev(f"""(function(){{var q={q};var l=q.querySelector('.options');
      return {{max:l.dataset.max,boxes:l.querySelectorAll('input[type=checkbox]').length,
               count:q.querySelector('.choice-count').textContent,live:q.querySelector('.choice-count').getAttribute('aria-live'),
               described:q.getAttribute('aria-describedby')}}}})()""")
    check("ins_025 the group declares its maximum", info["max"] == "4", info)
    check("ins_025 the count starts at 0 of 4", info["count"] == "0 of 4 chosen", info)
    check("ins_025 the count is a live region described by the group", info["live"] == "polite" and "c" in (info["described"] or ""), info)

    def boxes():
        return f"[...{q}.querySelectorAll('input[type=checkbox]')]"

    for k in range(4):
        await b.ev(f"{boxes()}[{k}].click()")
    state = await b.ev(f"""({boxes()}).map(b=>({{c:b.checked,d:b.disabled}}))""")
    count = await b.ev(f"{q}.querySelector('.choice-count').textContent")
    check("ins_025 four ticks read 4 of 4 chosen", count == "4 of 4 chosen", count)
    check("ins_025 at the limit the unticked options are unavailable",
          all(s["d"] for s in state[4:]) and all(s["c"] and not s["d"] for s in state[:4]), state)
    await b.ev(f"{boxes()}[4].click()")
    fifth = await b.ev(f"{boxes()}[4].checked")
    check("ins_025 a fifth option cannot be ticked", fifth is False, fifth)
    # Even forced, a fifth would be flagged and the count honest about it, never silently kept.
    await b.ev(f"{boxes()}[0].click()")
    state = await b.ev(f"""({boxes()}).map(b=>({{c:b.checked,d:b.disabled}}))""")
    count = await b.ev(f"{q}.querySelector('.choice-count').textContent")
    check("ins_025 unticking frees the other options", all(not s["d"] for s in state) and count == "3 of 4 chosen", (state, count))

    # Keyboard: Tab to the fifth option's box and press Space (the group has 3 ticked).
    await b.ev(f"{boxes()}[4].focus()")
    await b.key(" ", "Space", 32, " ")
    state = await b.ev(f"""({boxes()}).map(b=>({{c:b.checked,d:b.disabled}}))""")
    count = await b.ev(f"{q}.querySelector('.choice-count').textContent")
    check("ins_025 the space bar ticks the fourth option", state[4]["c"] and count == "4 of 4 chosen", (state, count))
    await b.ev("document.activeElement.blur()")
    await b.ev(f"{boxes()}[5].focus()")
    focused = await b.ev(f"document.activeElement === {boxes()}[5]")
    await b.key(" ", "Space", 32, " ")
    sixth = await b.ev(f"{boxes()}[5].checked")
    check("ins_025 the keyboard cannot tick past the limit", focused is False and sixth is False, (focused, sixth))

    # The glue reads the checked boxes: exactly four codes.
    n = await b.ev(f"{boxes()}.filter(b=>b.checked).length")
    check("ins_025 no more than four codes can be read from the group", n == 4, n)

    # A nonresponse clears the group and frees every option.
    pressed = await b.ev(f"""(function(){{var q={q};var nr=q.querySelector('.nr-btn');if(!nr)return null;nr.click();
      return [...q.querySelectorAll('input[type=checkbox]')].every(b=>!b.checked&&!b.disabled)&&q.querySelector('.choice-count').textContent==='0 of 4 chosen'}})()""")
    check("ins_140 a nonresponse clears the group and releases the limit", pressed in (True, None), pressed)

    # ---- the stepper: amount eaten each time, 0.5..20 ------------------------------------
    sq = "[...document.querySelectorAll('.q[data-control=stepper]')].find(q=>/amount eaten/i.test(q.textContent))"
    await b.open(path, sq)
    sel = None
    sel = await b.ev(f"""(function(){{var q={sq};var i=q.querySelector('input[type=number]');i.id='fs-amount';return {{max:i.dataset.max,min:i.dataset.min,
        btns:q.querySelectorAll('.num-stepper__btn').length,cls:i.className}}}})()""")
    check("ins_027 the stepper declares its bounds and has - / value / + buttons",
          sel["max"] == "20" and sel["min"] == "0.5" and sel["btns"] == 2 and "num-stepper__value" in sel["cls"], sel)

    def amount():
        return "document.getElementById('fs-amount')"

    await b.type_text("#fs-amount", "100")
    await b.ev(f"{amount()}.dispatchEvent(new Event('change',{{bubbles:true}}))")
    st = await b.ev(f"({{v:{amount()}.value,c:{amount()}.getAttribute('data-canonical'),m:{sq}.querySelector('.field-error').textContent,"
                    f"h:{sq}.querySelector('.field-error').hidden}})")
    check("ins_027 typing 100 into a field that stops at 20 is refused", st["c"] != "100" and st["v"] != "100", st)
    check("ins_027 the refusal is said inline", st["m"] == "At most 20 oz." and st["h"] is False, st)
    # Typing 2 then 0 is fine; one more 0 would make 200 and is refused.
    await b.ev(f"{amount()}.value='';{amount()}.dispatchEvent(new Event('input',{{bubbles:true}}))")
    await b.type_text("#fs-amount", "2")
    await b.send("Input.insertText", text="0")
    st = await b.ev(f"({{v:{amount()}.value,c:{amount()}.getAttribute('data-canonical')}})")
    check("ins_027 typing 20 is accepted", st == {"v": "20", "c": "20"}, st)
    await b.send("Input.insertText", text="0")
    st = await b.ev(f"({{v:{amount()}.value,c:{amount()}.getAttribute('data-canonical')}})")
    check("ins_027 a further digit (200) is refused and the value stays 20", st == {"v": "20", "c": "20"}, st)
    # Below the minimum is flagged, unread, and put back when the collector leaves the field.
    await b.ev(f"{amount()}.value='';{amount()}.dispatchEvent(new Event('input',{{bubbles:true}}))")
    await b.type_text("#fs-amount", "0")
    st = await b.ev(f"({{c:{amount()}.getAttribute('data-canonical'),i:{amount()}.getAttribute('aria-invalid'),m:{sq}.querySelector('.field-error').textContent}})")
    check("ins_027 0 (below 0.5) is flagged and has no canonical value", st["c"] is None and st["i"] == "true" and st["m"] == "At least 0.5 oz.", st)
    await b.type_text("#fs-amount", "")
    await b.ev(f"{amount()}.value='0.3';{amount()}.dispatchEvent(new Event('input',{{bubbles:true}}));{amount()}.dispatchEvent(new Event('change',{{bubbles:true}}))")
    st = await b.ev(f"({{v:{amount()}.value,c:{amount()}.getAttribute('data-canonical')}})")
    check("ins_163 0.3 is off the 0.5 grid and refused", st["c"] is None and st["v"] == "", st)

    # + stops at the maximum; - stops at the minimum.
    await b.ev(f"{amount()}.value='';{amount()}.dispatchEvent(new Event('input',{{bubbles:true}}))")
    plus = f"{sq}.querySelector('.num-stepper__btn[data-dir=\"1\"]')"
    minus = f"{sq}.querySelector('.num-stepper__btn[data-dir=\"-1\"]')"
    await b.ev(f"{plus}.click()")
    first = await b.ev(f"{amount()}.value")
    check("ins_022 the first press sets the start value (1)", first == "1", first)
    for _ in range(60):
        await b.ev(f"{plus}.click()")
    st = await b.ev(f"({{v:{amount()}.value,c:{amount()}.getAttribute('data-canonical')}})")
    check("ins_027 + stops at the maximum", st == {"v": "20", "c": "20"}, st)
    dis = await b.ev(f"({{p:{plus}.disabled,m:{minus}.disabled}})")
    check("ins_027 the + button is off at the maximum and - is on", dis == {"p": True, "m": False}, dis)
    for _ in range(80):
        await b.ev(f"{minus}.click()")
    st = await b.ev(f"({{v:{amount()}.value,c:{amount()}.getAttribute('data-canonical')}})")
    dis = await b.ev(f"({{p:{plus}.disabled,m:{minus}.disabled}})")
    check("ins_027 - stops at the minimum, with - off", st == {"v": "0.5", "c": "0.5"} and dis == {"p": False, "m": True}, (st, dis))

    # ---- money typed above its maximum --------------------------------------------------
    mq = "[...document.querySelectorAll('.q[data-control=money]')].find(q=>q.querySelector('input[data-max]'))"
    await b.open(path, mq)
    await b.ev(f"{mq}.querySelector('input').id='fs-money'")
    await b.type_text("#fs-money", "500")
    await b.ev("document.getElementById('fs-money').dispatchEvent(new Event('change',{bubbles:true}))")
    st = await b.ev(f"({{c:document.getElementById('fs-money').getAttribute('data-canonical'),i:document.getElementById('fs-money').getAttribute('aria-invalid'),m:{mq}.querySelector('.field-error').textContent}})")
    check("ins_027 money above its maximum has no canonical value and is flagged", st["c"] is None and st["i"] == "true" and "200" in st["m"], st)
    await b.ev("var m=document.getElementById('fs-money');m.value='12.505';m.dispatchEvent(new Event('change',{bubbles:true}))")
    st = await b.ev("document.getElementById('fs-money').getAttribute('data-canonical')")
    check("ins_162 money with too many minor digits has no canonical value", st is None, st)
    await b.ev("var m=document.getElementById('fs-money');m.value='12.5';m.dispatchEvent(new Event('change',{bubbles:true}))")
    st = await b.ev("document.getElementById('fs-money').getAttribute('data-canonical')")
    check("ins_027 an in-range amount is kept", st == "12.5", st)

    # ---- measurement pair: tolerance is a verdict, not a refusal (INS-026) ----------------
    pq = "[...document.querySelectorAll('.q[data-control=measurement-pair]')].find(q=>q.querySelector('.pair[data-tolerance]'))"
    await b.open(path, pq)
    st = await b.ev(f"""(function(){{var q={pq};var f=q.querySelectorAll('input');
      function set(i,v){{i.value=v;i.dispatchEvent(new Event('input',{{bubbles:true}}));i.dispatchEvent(new Event('change',{{bubbles:true}}))}}
      var lo=f[0].dataset.min, hi=f[0].dataset.max; var big=String(Number(hi)+100);
      set(f[0],big); var refused=f[0].getAttribute('data-canonical')===null&&f[0].getAttribute('aria-invalid')==='true';
      set(f[0],String(Number(lo)+10)); set(f[1],String(Number(lo)+30));
      return {{refused:refused,c0:f[0].getAttribute('data-canonical'),c1:f[1].getAttribute('data-canonical'),
              msg:q.querySelector('.field-error').textContent}}}})()""")
    check("ins_027 a reading above the maximum is refused", st["refused"], st)
    check("ins_026 readings further apart than the tolerance are kept and flagged",
          st["c0"] is not None and st["c1"] is not None and "agree" in st["msg"], st)


async def water(b, path):
    # ---- exclusive codes (INS-133) --------------------------------------------------------
    q = "[...document.querySelectorAll('.q')].find(q=>q.querySelector('input[type=checkbox][data-exclusive]'))"
    await b.open(path, q)
    r = await b.ev(f"""(function(){{var q={q};var bx=[...q.querySelectorAll('input[type=checkbox]')];
      var ex=bx.find(b=>b.hasAttribute('data-exclusive')); var others=bx.filter(b=>b!==ex);
      others[0].click(); others[1].click();
      var two=others[0].checked&&others[1].checked;
      ex.click();
      var cleared=!others[0].checked&&!others[1].checked&&ex.checked;
      others[0].click();
      var released=!ex.checked&&others[0].checked;
      return {{two:two,cleared:cleared,released:released}}}})()""")
    check("ins_133 an exclusive option clears the others", r["two"] and r["cleared"], r)
    check("ins_133 choosing another option clears the exclusive one", r["released"], r)

    # ---- a small bounded whole number is a stepper -----------------------------------------
    nq = "[...document.querySelectorAll('.q')].find(q=>q.querySelector('.num-stepper input[data-number][data-decimals=\"0\"]'))"
    await b.open(path, nq)
    r = await b.ev(f"""(function(){{var q={nq};var i=q.querySelector('input');var bs=q.querySelectorAll('.num-stepper__btn');
      var plus=q.querySelector('[data-dir="1"]'),minus=q.querySelector('[data-dir="-1"]');
      var hi=Number(i.dataset.max);
      for(var k=0;k<hi+5;k++) plus.click();
      var top={{v:i.value,c:i.getAttribute('data-canonical'),pd:plus.disabled,max:i.dataset.max}};
      i.value=String(hi+70); i.dispatchEvent(new Event('input',{{bubbles:true}})); i.dispatchEvent(new Event('change',{{bubbles:true}}));
      var typed={{c:i.getAttribute('data-canonical'),inv:i.getAttribute('aria-invalid'),msg:q.querySelector('.field-error').textContent}};
      return {{top:top,typed:typed}}}})()""")
    check("ins_027 + stops at the maximum of a bounded whole number", r["top"]["c"] == r["top"]["max"] and r["top"]["pd"] is True, r)
    check("ins_027 a typed value past the maximum is not kept", r["typed"]["c"] is None and r["typed"]["inv"] == "true" and r["typed"]["msg"], r)

    # ---- a date outside its bounds is emptied when the collector leaves it ------------------
    dq = "[...document.querySelectorAll('.q')].find(q=>q.querySelector('input[type=date][max]'))"
    await b.open(path, dq)
    r = await b.ev(f"""(function(){{var q={dq};var i=q.querySelector('input');i.id='fs-date';
      i.value='2099-01-01'; i.dispatchEvent(new Event('change',{{bubbles:true}}));
      var flagged=i.getAttribute('aria-invalid')==='true'&&q.querySelector('.field-error').textContent.length>0;
      i.dispatchEvent(new Event('blur'));
      return {{flagged:flagged,value:i.value}}}})()""")
    check("ins_027 a date past its maximum is flagged, then emptied on leaving", r["flagged"] and r["value"] == "", r)


async def main(food_html, water_html):
    b = Browser()
    try:
        await b.start()
        await food(b, food_html)
        await water(b, water_html)
        check("the page raised no script errors", not b.errors, b.errors[:2])
    finally:
        b.close()
    print(f"{'FAILED' if FAILED else 'OK'}: {len(FAILED)} failing check(s)")
    return 1 if FAILED else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))
