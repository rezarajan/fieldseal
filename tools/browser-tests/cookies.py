#!/usr/bin/env python3
"""Control 4 of the design's section 7.2: the browser never sends the factory's or the intake
portal's cookies to the collector stand-in.

The services run on `localhost` (Keycloak needs it for passkeys) and the stand-in on
`127.0.0.1`, so the browser keeps them apart. The script drives headless Chromium: it visits the
sign-in of the factory and of the intake portal (each sets its cookie on `localhost`), completes
the sign-in when the identity provider is the development IdP (`login_hint`), then requests
every page of the stand-in and asserts that no request to it carried a cookie, that the browser
holds no cookie for its address, and, as the positive control, that the browser does hold the
services' cookies for `localhost` and sends them there.

    cookies.py COLLECTOR_URL [FACTORY_URL [PORTAL_URL]] [--login NAME]

Defaults: http://127.0.0.1:8090, http://localhost:8080, http://localhost:8481. `--login NAME`
completes the sign-in as that development login (the development IdP only); without it the
script stops at the identity provider, which is all the stack's Keycloak allows without a
passkey, and checks the cookies the sign-in start set. Exit 0 when every check passes.
"""
import asyncio
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from axe_run import B  # noqa: E402  (the shared browser driver)

PAGES = ["/demo", "/demo/3", "/instruments", "/instruments/household-water-access", "/publishing", "/registration", "/device", "/healthz"]
NAMES = ("fs_session", "fs_intake_session")


def host_of(url):
    return urllib.parse.urlsplit(url).hostname


def origin_of(url):
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


async def main(argv):
    login = None
    if "--login" in argv:
        i = argv.index("--login")
        login = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    collector = (argv[0] if argv else "http://127.0.0.1:8090").rstrip("/")
    factory = (argv[1] if len(argv) > 1 else "http://localhost:8080").rstrip("/")
    portal = (argv[2] if len(argv) > 2 else "http://localhost:8481").rstrip("/")
    failures = []

    def check(ok, what):
        print(("  ok    " if ok else "  FAIL  ") + what)
        if not ok:
            failures.append(what)

    if host_of(collector) == host_of(factory):
        check(False, f"the collector stand-in and the factory share the host {host_of(collector)}: the browser would send them each other's cookies")
        return 1
    sent = []  # (request id, Cookie header or "") of every request the browser made
    urls = {}  # request id -> url

    class Recording(B):
        """The shared driver, keeping the network events that arrive while it waits for a reply."""

        def note(self, m):
            p = m.get("params", {})
            if m.get("method") == "Network.requestWillBeSentExtraInfo":
                sent.append((p["requestId"], {k.lower(): v for k, v in p["headers"].items()}.get("cookie", "")))
            elif m.get("method") == "Network.requestWillBeSent":
                urls[p["requestId"]] = p["request"]["url"]

        async def send(self, m, **pa):
            self.n += 1
            i = self.n
            await self.ws.send(json.dumps({"id": i, "method": m, "params": pa}))
            while True:
                r = json.loads(await self.ws.recv())
                if r.get("id") == i:
                    return r
                self.note(r)

    b = Recording()
    await b.start(1280, 900)
    await b.send("Network.enable")

    async def pump(seconds):
        """Lets the page load and takes the network events that come with it."""
        try:
            while True:
                b.note(json.loads(await asyncio.wait_for(b.ws.recv(), seconds)))
        except asyncio.TimeoutError:
            pass

    # Sign in at the factory and at the intake portal; each answer lands on localhost.
    for name, base in (("factory", factory), ("intake portal", portal)):
        await b.send("Page.navigate", url=base + "/sign-in")
        await pump(2.0)
        here = await b.ev("location.href")
        if login and here and "login_hint" not in here and origin_of(here) != origin_of(base):
            await b.send("Page.navigate", url=here + ("&" if "?" in here else "?") + "login_hint=" + urllib.parse.quote(login))
            await pump(3.0)
            here = await b.ev("location.href")
            check(bool(here) and origin_of(here) == origin_of(base), f"the {name} sign-in as {login} returns to {base}")
    cookies = (await b.send("Network.getAllCookies"))["result"]["cookies"]
    held = {(c["name"], c["domain"].lstrip(".")) for c in cookies}
    service_cookies = [c for c in cookies if host_of(factory) == c["domain"].lstrip(".")]
    check(len(service_cookies) > 0, f"the browser holds cookies for {host_of(factory)} after the sign-in starts: {sorted(n for n, _ in held)}")
    if login:
        check(any(n in NAMES for n, _ in held), f"a session cookie ({' or '.join(NAMES)}) is held after the sign-in")

    # Every stand-in page, then the positive control: the services get their cookie.
    mark = len(sent)
    for path in PAGES:
        await b.send("Page.navigate", url=collector + path)
        await pump(1.5)
    after = {rid: cookie for rid, cookie in sent[mark:]}
    to_collector = {rid: cookie for rid, cookie in after.items() if urls.get(rid, "").startswith(collector)}
    check(len(to_collector) >= len(PAGES), f"the browser requested the stand-in's pages ({len(to_collector)} requests)")
    check(all(cookie == "" for cookie in to_collector.values()), "no request to the stand-in carried a Cookie header")
    check(not any(n in c for c in to_collector.values() for n in NAMES), "none of them carried fs_session or fs_intake_session")
    got = (await b.send("Network.getCookies", urls=[collector]))["result"]["cookies"]
    check(len(got) == 0, f"the browser holds no cookie for {collector}: {[c['name'] for c in got]}")
    check(await b.ev("document.cookie") == "", "the stand-in's pages see no cookie")

    mark = len(sent)
    await b.send("Page.navigate", url=factory + "/")
    await pump(2.0)
    to_factory = [cookie for rid, cookie in sent[mark:] if urls.get(rid, "").startswith(factory)]
    check(any(cookie for cookie in to_factory), f"positive control: the browser does send its cookies to the factory ({len(to_factory)} requests)")
    b.proc.kill()
    print("cookie scoping:", "ok" if not failures else f"{len(failures)} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
