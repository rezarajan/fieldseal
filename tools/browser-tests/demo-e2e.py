#!/usr/bin/env python3
"""CUJ 4 end to end: the eight steps of the guided demo, run headless against a running `just web`.

Every step is done by the component that does it in production: the command-line steps run the
real `fieldseal` and `tools/dev-publish.sh`; the factory portal and the results reader are used
through the browser with a sign-in at the development IdP; the device is the Device page, driven
by device-flow.js. The guided demo (/demo/N) is then read, and each confirmation it carries is
compared with the place where the same value exists on its own: the CLI output, the transparency
log, the factory's registration state and its own output (factory.log), the file the browser
downloaded, and the results reader.

    demo-e2e.py [--collector URL] [--factory URL] [--results URL] [--log URL] [--state DIR]

Defaults are those of `just web`. Environment: FIELDSEAL_BIN (the CLI; default target/debug/fieldseal).
Exit 0 only when every check passes.
"""
import asyncio
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
from axe_run import B  # noqa: E402  (the shared browser driver)

ARGS = dict(zip(sys.argv[1::2], sys.argv[2::2]))
COLLECTOR = ARGS.get("--collector", "http://127.0.0.1:8090").rstrip("/")
FACTORY = ARGS.get("--factory", "http://localhost:8080").rstrip("/")
RESULTS = ARGS.get("--results", "http://localhost:8481").rstrip("/")
LOG = ARGS.get("--log", "http://localhost:9001").rstrip("/")
IDP = "http://localhost:8180/realms/fieldseal"
STATE = ARGS.get("--state", os.path.join(ROOT, "deploy", "local", ".state", "dev-web"))
FACTORY_LOG = os.path.join(STATE, "logs", "factory.log")
FS = os.environ.get("FIELDSEAL_BIN") or os.path.join(ROOT, "target", "debug", "fieldseal")
LOGIN = "presenter"

failures = []


def check(ok, what, detail=""):
    print(("  ok    " if ok else "  FAIL  ") + what + ("" if ok or not detail else f"  -> {detail}"), flush=True)
    if not ok:
        failures.append(what)


def section(title):
    print(f"\n== {title}", flush=True)


def run(cmd, env=None, cwd=ROOT, ok_codes=(0,)):
    """Runs a command line tool; returns (code, output). The command is printed, as a presenter would see it."""
    print("  $ " + " ".join(os.path.relpath(c, ROOT) if c.startswith(ROOT) else c for c in cmd), flush=True)
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
    out = (p.stdout + p.stderr).strip()
    for line in out.splitlines()[:6]:
        print("    " + line[:200], flush=True)
    return p.returncode, out


def cli_env():
    """The CLI's sign-in settings only, as tools/dev-web.sh gives it (the development IdP, no secret)."""
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp"), "FIELDSEAL_OIDC_ISSUER": IDP, "FIELDSEAL_OIDC_CLIENT_ID": "fieldseal-cli"}
    return env


def http_get(url, timeout=15):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read()


def checkpoint_size():
    """The log's tree size, from the first lines of its signed checkpoint note (origin, size, root)."""
    return int(http_get(LOG + "/checkpoint")[1].decode().split("\n")[1])


def factory_events(name):
    if not os.path.exists(FACTORY_LOG):
        return []
    out = []
    for line in open(FACTORY_LOG, errors="replace"):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event") == name:
            out.append(e)
    return out


async def until_async(fn, what, seconds=60, every=0.5):
    end = time.time() + seconds
    last = None
    while time.time() < end:
        try:
            last = await fn()
            if last:
                return last
        except Exception as e:  # noqa: BLE001  (not yet)
            last = e
        await asyncio.sleep(every)
    raise RuntimeError(f"timed out waiting for {what}: {last}")


def until_sync(fn, what, seconds=60, every=0.5):
    end = time.time() + seconds
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    raise RuntimeError(f"timed out waiting for {what}")


class Tab:
    """One browser tab over the DevTools protocol (the shared profile holds the cookies)."""

    def __init__(self, ws, port):
        self.ws, self.n, self.port = ws, 0, port
        self.errors = []

    @classmethod
    async def open(cls, browser, url="about:blank"):
        import websockets

        req = urllib.request.Request(f"http://127.0.0.1:{browser.port}/json/new?{urllib.parse.quote(url, safe=':/?&=')}", method="PUT")
        t = json.load(urllib.request.urlopen(req))
        tab = cls(await websockets.connect(t["webSocketDebuggerUrl"], max_size=None), browser.port)
        await tab.send("Runtime.enable")
        await tab.send("Page.enable")
        return tab

    async def send(self, method, **params):
        self.n += 1
        i = self.n
        await self.ws.send(json.dumps({"id": i, "method": method, "params": params}))
        while True:
            m = json.loads(await self.ws.recv())
            if m.get("method") == "Runtime.exceptionThrown":
                self.errors.append("EXC " + json.dumps(m["params"]["exceptionDetails"])[:300])
            elif m.get("id") == i:
                return m

    async def ev(self, expr, timeout=170):
        await self.send("Page.bringToFront")  # a tab behind another has its timers slowed down
        r = await asyncio.wait_for(self.send("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True), timeout)
        res = r.get("result", {})
        if "exceptionDetails" in res:
            d = res["exceptionDetails"]
            raise RuntimeError(d.get("exception", {}).get("description", d.get("text", "script error")))
        return res.get("result", {}).get("value")

    async def goto(self, url, settle=0.3):
        """Navigates and waits until the new document has loaded (a redirect may change the address)."""
        await self.send("Page.navigate", url=url)
        await asyncio.sleep(0.2)
        end = time.time() + 30
        while time.time() < end:
            try:
                if await self.ev("document.readyState === 'complete' && location.href !== 'about:blank'"):
                    break
            except RuntimeError:
                pass
            await asyncio.sleep(0.2)
        await asyncio.sleep(settle)

    async def text(self, selector):
        return await self.ev(f"(document.querySelector({json.dumps(selector)})||{{}}).textContent")


class Browser:
    def __init__(self):
        self.b = B()

    async def start(self):
        await self.b.start(1280, 900)
        self.proc = self.b.proc
        self.port = int(next(a.split("=")[1] for a in self.proc.args if a.startswith("--remote-debugging-port=")))

    async def tab(self, url="about:blank"):
        return await Tab.open(self, url)


async def sign_in(tab, base):
    """Signs the tab in at a service through the development IdP's page as `presenter` (login_hint)."""
    await tab.goto(base + "/sign-in", 1.5)
    here = await tab.ev("location.href")
    if "login_hint" not in here and not here.startswith(base):
        await tab.goto(here + ("&" if "?" in here else "?") + "login_hint=" + LOGIN, 2.0)
    await until_async(lambda: tab.ev(f"location.href.startsWith({json.dumps(base)})"), f"the sign-in at {base} to return")


async def portal_html(tab):
    await tab.goto(FACTORY + "/", 0.8)
    return await tab.ev("document.documentElement.outerHTML")


async def portal_post(tab, action, extra=None):
    """Submits a form of the factory portal as its page would, with the page's CSRF token. (The
    portal's content security policy allows form posts to itself, not scripted requests.)"""
    body = {"csrf": await tab.ev("document.querySelector('input[name=csrf]').value")}
    body.update(extra or {})
    inputs = "".join(f"i=document.createElement('input');i.type='hidden';i.name={json.dumps(k)};i.value={json.dumps(v)};f.append(i);" for k, v in body.items())
    await tab.ev(f"(()=>{{const f=document.createElement('form');f.method='post';f.action={json.dumps(action)};let i;{inputs}window.__old=true;document.body.append(f);setTimeout(()=>f.submit(),0);return 1}})()")
    await until_async(lambda: tab.ev("!window.__old && document.readyState === 'complete'"), "the portal to answer")
    return {"url": await tab.ev("location.href"), "text": await tab.ev("document.documentElement.outerHTML")}


class Facts(dict):
    """The facts of a confirmation panel: key to value, with `.label` and `.source` (where it was read) by key."""


async def demo_facts(tab, n, wait_for=None):
    """Opens /demo/n and returns {data-fact: text of its dd} once the script has filled the panel."""
    await tab.goto(f"{COLLECTOR}/demo/{n}", 0.8)

    async def read():
        rows = await tab.ev("[...document.querySelectorAll('#facts [data-fact]')].map(e=>[e.dataset.fact,e.querySelector('dt').textContent,e.querySelector('.value').textContent,[...e.querySelectorAll('.tag')].map(t=>t.textContent).join(' | ')])")
        facts = Facts({k: v for k, _, v, _ in rows or []})
        facts.label = {k: label for k, label, _, _ in rows or []}
        facts.source = {k: source for k, _, _, source in rows or []}
        return facts if rows and (wait_for is None or wait_for(facts)) else None

    return await until_async(read, f"the confirmation of /demo/{n}", 30)


async def main():
    work = tempfile.mkdtemp(prefix="demo-e2e-")
    downloads = os.path.join(work, "downloads")
    os.makedirs(downloads)
    browser = Browser()
    await browser.start()
    try:
        await steps(browser, work, downloads)
    finally:
        browser.proc.kill()
        shutil.rmtree(work, ignore_errors=True)
    print("\nRESULT", f"FAILED: {len(failures)} check(s): " + "; ".join(failures) if failures else "all eight steps passed")
    return 1 if failures else 0


async def steps(browser, work, downloads):
    demo = await browser.tab()
    portal = await browser.tab()
    device = await browser.tab()
    results = await browser.tab()

    # ---- step 1: compile the survey ---------------------------------------------------------
    section("1 Compile the survey")
    survey = "school-meals-baseline"
    code, out = run([FS, "survey", "check", f"examples/surveys/{survey}"])
    check(code == 0 and "no errors" in out, "the CLI compiles the survey without errors")
    code, hashed = run([FS, "instrument", "hash", f"examples/surveys/{survey}/instrument.yaml"])
    await demo.goto(f"{COLLECTOR}/demo/1", 0.8)
    row = await demo.ev(f"(document.querySelector('tr[data-survey={survey}]')||{{}}).textContent")
    check(bool(row) and hashed.strip() in row, "the instrument address on /demo/1 is the CLI's `instrument hash` output", f"{hashed.strip()} / {row}")
    for layout in sorted(os.listdir(os.path.join(ROOT, "examples", "surveys", survey, "layouts"))):
        name = layout.rsplit(".", 1)[0]
        check(bool(row) and name in row, f"/demo/1 lists the {name} layout")

    # ---- step 2: publish to the factory ------------------------------------------------------
    section("2 Publish to the factory")
    surveys_root = os.path.join(work, "surveys")
    os.makedirs(surveys_root)
    name = "demo-visit-" + str(os.getpid())
    code, _ = run([FS, "new", "survey", name, "--root", surveys_root])
    check(code == 0, "a new survey is scaffolded")
    before = checkpoint_size()
    code, out = run([os.path.join(ROOT, "tools", "dev-publish.sh"), os.path.join(surveys_root, name)], env=dict(os.environ, FIELDSEAL_BIN=FS))
    check(code == 0, "just publish (tools/dev-publish.sh) publishes the survey", out[-300:])
    address = (re.search(rf"published {re.escape(name)} \S+ at (sha256:[0-9a-f]+)", out) or [None, ""])[1]
    after = checkpoint_size()
    check(after > before, f"the log's own checkpoint grew ({before} to {after})")
    await demo.goto(f"{COLLECTOR}/demo/2", 0.8)
    shown = await demo.ev(f"(document.querySelector('tr[data-artefact={name}]')||{{}}).textContent")
    check(bool(shown) and address in shown, "the publication address on /demo/2 is the CLI's output", f"{address} / {shown}")
    check("verified" in (shown or "") and "2 of 2" in (shown or ""), "/demo/2 shows the publication verified, with two of two signatures", shown)
    check((await demo.text("#log-size")) == str(after), "the log size on /demo/2 is the size in the log's checkpoint", f"{await demo.text('#log-size')} / {after}")

    # ---- step 3: register a device ------------------------------------------------------------
    section("3 Register a device")
    await sign_in(portal, FACTORY)
    check("Signed in as" in (await portal_html(portal)), "signed in at the factory portal through the development IdP")
    html = await portal_html(portal)
    for tenancy in re.findall(r'action="/devices/([^"/]*)/retire"', html):
        await portal_post(portal, f"/devices/{tenancy}/retire")
    check("/retire" not in await portal_html(portal), "any live device of an earlier run is retired (REG-043)")
    await portal.goto(FACTORY + "/", 0.5)
    r = await portal_post(portal, "/tokens", {"route": "online"})
    token = (re.search(r'<p class="token">([^<]+)</p>', r["text"]) or [None, ""])[1]
    check(token.startswith("FS1T:"), "the portal issues a registration token")

    await device.goto(COLLECTOR + "/device", 2.0)
    await device.ev(open(os.path.join(HERE, "device-flow.js")).read() + ";1")
    await device.ev(f"window.INSTRUMENT='household-water-access';window.TOKEN={json.dumps(token)};1")

    async def flow(name):
        try:
            await device.ev(f"window.flowStep({json.dumps(name)})")
        except RuntimeError:
            # The device's own log says why a screen was not reached.
            log = await device.ev("[...document.querySelectorAll('#log li')].slice(-6).map(x=>x.textContent)")
            print(f"  device step {name} failed; the device's log ends:", *[f"\n    {line[:240]}" for line in log or []], f"\n    bundle: {await device.text('#bundle-status')} {await device.text('#bundle-error')}")
            raise

    await flow("starts")
    await flow("pin")
    await flow("register")
    words = await device.ev("window.__words")
    tenancy = await device.ev("window.__tenancy")
    html = await portal_html(portal)
    portal_words = " ".join(re.sub(r"<[^>]+>", " ", (re.search(r'class="words">(.*?)</p>', html, re.S) or [None, ""])[1]).split())
    norm = lambda s: re.sub(r"[^a-z ]", "", s.lower()).split()  # noqa: E731  (numbers dropped)
    check(bool(words) and norm(words) == norm(portal_words), "the four words on the device are the four words in the factory portal", f"{words!r} / {portal_words!r}")
    await portal_post(portal, f"/pending/{tenancy}/confirm")
    await flow("registered")
    state = json.loads(http_get(f"{FACTORY}/v1/registrations/{tenancy}")[1])
    check(state.get("state") == "registered", "the factory reports the device registered (GET /v1/registrations)", state)
    facts = await demo_facts(demo, 3, lambda v: "registered" in v.get("state", ""))
    check(facts["tenancy"] == tenancy and "device's own view" in facts.source["tenancy"], "/demo/3 shows the tenancy, labelled as the device's own view")
    check(facts["state"] == "registered" and "factory" in facts.source["state"], "/demo/3 shows state registered, read from the factory", facts["state"])
    check(tenancy[:16] in await portal_html(portal), "the factory portal lists the device (its first 16 digits)")

    # ---- step 4: load the published bundle ---------------------------------------------------
    section("4 Load the published bundle")
    event = until_sync(lambda: next((e for e in factory_events("bundle-built") if e["tenancy"] == tenancy[:16] and e["sequence"] == 1), None), "the factory's bundle-built event for sequence 1")
    check(True, "factory.log has bundle-built for this tenancy, sequence 1", event)
    await flow("bundle")
    facts = await demo_facts(demo, 4, lambda v: "sequence" in v and any(k.startswith("publication-") for k in v))
    check(facts["sequence"] == str(event["sequence"]) and "device" in facts.source["sequence"], "/demo/4 shows the bundle sequence the factory logged", f"{facts['sequence']} / {event}")
    check(".fsb" in facts["file"] or "bundle" in facts["file"], "/demo/4 shows the bundle file name from the factory's headers", facts["file"])
    pubs = [v for k, v in facts.items() if k.startswith("publication-")]
    sources = [facts.source[k] for k in facts if k.startswith("publication-")]
    check(len(pubs) >= 3 and all("listed in step 2" in s for s in sources), "each publication the device verified is listed on /demo/2", sources)

    # ---- step 5: manage rosters ---------------------------------------------------------------
    section("5 Manage rosters")
    store = os.path.join(STATE, "rosters")

    def stored_latest():
        _, text = run([FS, "roster", "list", "--store", store, "--json"])
        found = [r for r in json.loads(text)["rosters"] if r["cohort"] == "village-a"]
        return max(found, key=lambda r: r["version"]) if found else None

    # The example file is version 4. A state that already holds it (a second run) gets the next
    # version of the same file, so the factory still has a new roster to journal.
    nxt = "examples/rosters/next/village-a.yaml"
    held_version = stored_latest()["version"]
    version = max(4, held_version + 1)
    if version != 4:
        nxt = os.path.join(work, "village-a.yaml")
        open(nxt, "w").write(open(os.path.join(ROOT, "examples/rosters/next/village-a.yaml")).read().replace("version: 4", f"version: {version}"))
    code, _ = run([FS, "roster", "check", nxt, "--instrument", "examples/surveys/household-water-access"])
    check(code == 0, "roster check passes")
    code, out = run([FS, "roster", "diff", f"village-a@{held_version}", nxt, "--store", store])
    check(code == 0, f"roster diff village-a@{held_version} against the next file")
    code, out = run([FS, "roster", "issue", "--factory-url", FACTORY, "--browser", "none", "--login", LOGIN, nxt], env=cli_env())
    check(code == 0, f"roster issue (signed in at the development IdP) issues version {version}", out[-300:])
    seq = 2
    event = until_sync(lambda: next((e for e in factory_events("bundle-built") if e["tenancy"] == tenancy[:16] and e["sequence"] == seq), None), "the factory's bundle-built event for sequence 2")
    check(True, "factory.log has bundle-built for sequence 2", event)
    await flow("newer")
    issued = stored_latest()
    facts = await demo_facts(demo, 5, lambda v: v.get("sequence") == str(seq))
    roster = next((v for k, v in facts.items() if k.startswith("roster-") and "village-a" in facts.label[k]), None)
    check(issued["version"] == version, f"roster list shows version {version} stored")
    check(roster is not None and roster.startswith(f"version {version},"), f"/demo/5 shows village-a at version {version} in the bundle the device holds", roster)
    want = f"{issued['subjects']} subject(s); consent: " + ", ".join(f"{n} {k}" for k, n in issued["consent"].items() if n)
    want = ", ".join(sorted(want.split(", ")))
    roster = ", ".join(sorted((roster or "").split(", ")))
    check(roster is not None and want in roster, "/demo/5 shows the subject and consent counts that roster list shows", f"{want} / {roster}")
    check("hh-000" not in json.dumps(facts), "/demo/5 shows no subject")

    # ---- step 6: conduct a survey -------------------------------------------------------------
    section("6 Conduct a survey")
    sealed = 0
    for person in range(2):
        for name in ("roster", "about", "foods", "integrity", "review", "seal"):
            await flow(name)
        sealed += 1
        if person == 0:
            await flow("next-person")
    facts = await demo_facts(demo, 6, lambda v: v.get("records") == str(sealed))
    check(facts["records"] == str(sealed) and "device's own view" in facts.source["records"], f"/demo/6 shows {sealed} sealed records, labelled as the device's own view", facts["records"])
    seq_from, seq_through = [int(x) for x in re.findall(r"\d+", facts["range"])[:2]]

    # ---- step 7: export -----------------------------------------------------------------------
    section("7 Export")
    await device.send("Page.setDownloadBehavior", behavior="allow", downloadPath=downloads)
    await flow("export")
    await flow("upload")
    await asyncio.sleep(1.0)
    files = os.listdir(downloads)
    check(len(files) == 1, "the browser downloaded one export file", files)
    digest = hashlib.sha256(open(os.path.join(downloads, files[0]), "rb").read()).hexdigest() if files else ""
    facts = await demo_facts(demo, 7, lambda v: "covered" in v and "export-sha256" in v)
    check(digest != "" and digest == facts["export-sha256"], "/demo/7 shows the SHA-256 of the file the browser saved", f"{digest} / {facts['export-sha256']}")
    check(files and files[0] == facts["export-name"], "/demo/7 shows the export file name", facts["export-name"])
    check(facts["covered"] == str(seq_through), "/demo/7 shows the receipt covering the last sealed sequence", facts["covered"])
    check("receipt" in facts and "verified" in facts["receipt"], "/demo/7 says the device verified the receipt against the trust bundle")

    # ---- step 8: read the results -------------------------------------------------------------
    section("8 Read the results")
    await demo.goto(f"{COLLECTOR}/demo/8", 0.8)
    link = await demo.ev("(document.querySelector('a.btn-primary')||{}).href")
    check(link == RESULTS + "/", "/demo/8 links to the results reader and shows nothing else", link)
    check(await demo.ev("document.querySelectorAll('#facts').length") == 0, "/demo/8 confirms nothing")
    await sign_in(results, RESULTS)
    await results.goto(RESULTS + "/results", 1.0)
    page = await results.ev("document.body.innerText")
    mark = int((re.search(r"Landing mark (\d+)", page) or [None, "-1"])[1])
    check(mark >= 1, "the results reader shows a landing mark after the upload", page[:200])
    cookie = "; ".join(f"{c['name']}={c['value']}" for c in (await results.send("Network.getCookies", urls=[RESULTS]))["result"]["cookies"])

    def download(name):
        """A download from the results reader, with the browser's session (the page's policy allows no scripted requests)."""
        req = urllib.request.Request(f"{RESULTS}/results/exports/{mark}/{name}", headers={"Cookie": cookie})
        return urllib.request.urlopen(req, timeout=30).read().decode()

    manifest = json.loads(download("manifest.json"))
    check(manifest["export_schema_version"], "the manifest names the export schema version", manifest.get("export_schema_version"))
    rows = {f["name"]: f.get("rows") for f in manifest["files"]}
    await demo.goto(f"{COLLECTOR}/demo/2", 0.5)
    step2 = await demo.ev("document.documentElement.outerHTML")
    landed = [i["address"] for i in manifest["instruments"]]
    check(bool(landed) and all(a in step2 for a in landed), "the instrument the export names is a publication listed on /demo/2", landed)
    check((rows.get("results.csv") or 0) > 0, "the manifest counts rows in results.csv", rows)
    csv_text = download("results.csv")
    table = list(csv.DictReader(io.StringIO(csv_text)))
    check(len(table) == rows.get("results.csv"), "results.csv has the rows the manifest counts", f"{len(table)} / {rows}")
    check({r["tenancy"] for r in table} == {tenancy}, "every row is the device's tenancy", {r["tenancy"] for r in table})
    check(len({r["record_id"] for r in table}) == sealed, f"the {sealed} sealed records landed", len({r["record_id"] for r in table}))
    check(all(seq_from <= int(r["seq"]) <= seq_through for r in table), "every row's sequence is in the range the device showed in /demo/6")
    got = hashlib.sha256(csv_text.encode()).hexdigest()
    wanted = next(f["sha256"] for f in manifest["files"] if f["name"] == "results.csv")
    check(got == wanted, "the downloaded results.csv has the SHA-256 the manifest names", f"{got} / {wanted}")

    # ---- the stepper itself ---------------------------------------------------------------------
    section("The stepper")
    for n in range(1, 9):
        await demo.goto(f"{COLLECTOR}/demo/{n}", 0.4)
        check(await demo.ev("document.querySelectorAll('.btn-primary').length") == 1, f"/demo/{n} has one primary action")
    check("just acceptance" in await demo.ev("document.body.innerText") and "just release" in await demo.ev("document.body.innerText"), "the last page names just acceptance and just release")
    # leave the factory as it was found for the next run
    await sign_in(portal, FACTORY)
    html = await portal_html(portal)
    for t in re.findall(r'action="/devices/([^"/]*)/retire"', html):
        await portal_post(portal, f"/devices/{t}/retire")
    for t in (demo, portal, device, results):
        if t.errors:
            print("  page errors:", t.errors[:3])


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
