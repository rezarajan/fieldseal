#!/usr/bin/env python3
"""Drives the Device page in headless Chromium over the DevTools protocol.

Loads BASE/device, evaluates device-flow.js (which defines `window.flow`, a list of
{name, shot?, run}) and runs the steps in order; each step returns once its screen is
reached. A step with `shot` also gets a 1280x820 screenshot saved into SHOTS.
Exits 0 when every check passes, 1 otherwise.

    BASE=http://127.0.0.1:18110 SHOTS=/tmp/shots INSTRUMENT=school-meals-baseline device-flow.py
"""
import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import websockets

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("BASE", "http://127.0.0.1:18110")
SHOTS = os.environ.get("SHOTS", "")
INSTRUMENT = os.environ.get("INSTRUMENT", "household-water-access")
WIDTH = int(os.environ.get("WIDTH", "1280"))
HEIGHT = int(os.environ.get("HEIGHT", "820"))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def main():
    port = free_port()
    profile = tempfile.mkdtemp(prefix="fieldseal-device-")
    proc = subprocess.Popen(
        ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", f"--remote-debugging-port={port}",
         f"--user-data-dir={profile}", f"--window-size={WIDTH},{HEIGHT}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failed = []
    try:
        tabs = None
        for _ in range(120):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                if any(t["type"] == "page" for t in tabs):
                    break
            except Exception:
                time.sleep(0.5)
        ws_url = [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        async with websockets.connect(ws_url, max_size=None) as ws:
            n = 0
            errors = []

            async def send(method, **params):
                nonlocal n
                n += 1
                i = n
                await ws.send(json.dumps({"id": i, "method": method, "params": params}))
                while True:
                    m = json.loads(await ws.recv())
                    if m.get("method") == "Runtime.exceptionThrown":
                        errors.append("EXC " + json.dumps(m["params"]["exceptionDetails"])[:300])
                    elif m.get("method") == "Runtime.consoleAPICalled" and m["params"]["type"] == "error":
                        errors.append("console.error " + " ".join(str(a.get("value", a.get("description"))) for a in m["params"]["args"])[:300])
                    elif m.get("id") == i:
                        return m

            await send("Runtime.enable")
            await send("Page.enable")
            await send("Emulation.setDeviceMetricsOverride", width=WIDTH, height=HEIGHT, deviceScaleFactor=1, mobile=False)
            await send("Page.navigate", url=BASE + "/device")
            await asyncio.sleep(2)
            js = open(os.environ.get("FLOW") or os.path.join(HERE, "device-flow.js")).read()
            await send("Runtime.evaluate", expression=f"window.INSTRUMENT={json.dumps(INSTRUMENT)};" + js)
            count = (await send("Runtime.evaluate", expression="window.flow.length", returnByValue=True))["result"]["result"]["value"]
            for k in range(count):
                r = await send("Runtime.evaluate", expression=f"window.flow[{k}].run()", awaitPromise=True, returnByValue=True, timeout=150000)
                res = r.get("result", {})
                if "exceptionDetails" in res:
                    d = res["exceptionDetails"]
                    print("FAIL step", k, d.get("exception", {}).get("description", d.get("text")))
                    failed.append(f"step {k}")
                    shot = await send("Page.captureScreenshot", format="png")
                    if SHOTS:
                        open(os.path.join(SHOTS, f"failed-step-{k}.png"), "wb").write(base64.b64decode(shot["result"]["data"]))
                    break
                info = (await send("Runtime.evaluate", expression=f"[window.flow[{k}].name, window.flow[{k}].shot||'']", returnByValue=True))["result"]["result"]["value"]
                if info[1] and SHOTS:
                    await asyncio.sleep(0.3)
                    s = await send("Page.captureScreenshot", format="png")
                    open(os.path.join(SHOTS, info[1]), "wb").write(base64.b64decode(s["result"]["data"]))
            checks = (await send("Runtime.evaluate", expression="window.__checks||[]", returnByValue=True))["result"]["result"]["value"]
            for name, ok, detail in checks:
                print(("PASS " if ok else "FAIL ") + name + ("" if not detail else "  -> " + str(detail)[:300]))
                if not ok:
                    failed.append(name)
            for e in errors:
                print("PAGE-ERROR", e)
            log = (await send("Runtime.evaluate", expression="[...document.querySelectorAll('#log li')].map(x=>x.textContent)", returnByValue=True))["result"]["result"]["value"]
            if failed and log:
                print("LOG", json.dumps(log[-8:], indent=1))
    finally:
        proc.terminate()
    print("RESULT", "FAILED: " + ", ".join(failed) if failed else "all checks passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
