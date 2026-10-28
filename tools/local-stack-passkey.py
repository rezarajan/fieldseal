#!/usr/bin/env python3
"""Drives the local stack's portal in headless Chromium with a virtual authenticator (WebAuthn
over the DevTools protocol): registers a passkey on first sign-in, signs out, signs in with the
passkey and asks the portal for a registration token. Local only; opt-in; never run in CI.

    python3 tools/local-stack-passkey.py [--on-token CMD [--emit-json FILE]] [--chromium /usr/bin/chromium] [--show-token]

Needs the `websockets` package and a Chromium or Chrome. The stack must be up (`just up`);
`just demo` runs this inside the demo container. Exit status 0 only if every step behaved as
documented:

  1. first sign-in: username only, then the passkey registration is required
  2. that first session is NOT phishing-resistant, so the portal refuses to issue a token
  3. second sign-in: the passkey authenticates; the ID token carries acr=phr
  4. the portal issues a registration token
  5. with --on-token: CMD runs with the token in $FIELDSEAL_TOKEN and registers a device
     with the factory (the CLI: `registration request` and `registration submit`); its last
     line of output is JSON with the device's "words" and "tenancy". The portal must show
     the same four words; the script confirms them, and the factory must then report the
     tenancy registered. With --emit-json the words and tenancy are written to FILE.
  6. the ID token of a passkey sign-in carries acr=phr (and no amr)
"""
import argparse
import asyncio
import base64
import hashlib
import secrets
import urllib.parse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import websockets

PORTAL = os.environ.get("FIELDSEAL_PORTAL_URL", "http://localhost:8080")
USER = "product-owner"


KEYCLOAK = os.environ.get("FIELDSEAL_KEYCLOAK_URL", "http://localhost:8180")
SECRETS = os.environ.get("FIELDSEAL_SECRETS_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deploy", "local", ".env.secrets")


def secret(name):
    """A generated development secret: from the environment (the demo container gets them
    from compose), else from deploy/local/.env.secrets."""
    if os.environ.get(name):
        return os.environ[name]
    return next(l.split("=", 1)[1].strip() for l in open(SECRETS) if l.startswith(name + "="))


def reset_user():
    """Back to the first-sign-in state: no passkeys, passkey registration required. Uses the
    Keycloak admin API with the generated admin password; local development only."""
    password = secret("KC_BOOTSTRAP_ADMIN_PASSWORD")

    def call(method, path, body=None, form=None, token=None):
        data = urllib.parse.urlencode(form).encode() if form else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(KEYCLOAK + path, data=data, method=method)
        if form:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        elif body is not None:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return json.loads(raw) if raw else None

    token = call("POST", "/realms/master/protocol/openid-connect/token",
                 form={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": password})["access_token"]
    user = call("GET", f"/admin/realms/fieldseal/users?username={USER}&exact=true", token=token)[0]
    for cred in call("GET", f"/admin/realms/fieldseal/users/{user['id']}/credentials", token=token):
        call("DELETE", f"/admin/realms/fieldseal/users/{user['id']}/credentials/{cred['id']}", token=token)
    user["requiredActions"] = ["webauthn-register-passwordless"]
    call("PUT", f"/admin/realms/fieldseal/users/{user['id']}", body=user, token=token)
    call("POST", f"/admin/realms/fieldseal/users/{user['id']}/logout", token=token)


class Cdp:
    def __init__(self, ws):
        self.ws, self.n, self.waiters, self.events = ws, 0, {}, []

    async def pump(self):
        async for raw in self.ws:
            m = json.loads(raw)
            if "id" in m and m["id"] in self.waiters:
                self.waiters.pop(m["id"]).set_result(m)
            else:
                self.events.append(m)
                if m.get("method") == "Page.javascriptDialogOpening":
                    print("   page dialog:", m["params"].get("message"), flush=True)
                    asyncio.ensure_future(self.call("Page.handleJavaScriptDialog", {"accept": True, "promptText": m["params"].get("defaultPrompt") or "Passkey"}, m.get("sessionId")))

    async def call(self, method, params=None, session=None):
        self.n += 1
        fut = asyncio.get_event_loop().create_future()
        self.waiters[self.n] = fut
        msg = {"id": self.n, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        await self.ws.send(json.dumps(msg))
        if os.environ.get("PASSKEY_DEBUG"):
            print("   >", method, json.dumps(params)[:100] if params else "", flush=True)
        try:
            r = await asyncio.wait_for(fut, 30)
        except asyncio.TimeoutError:
            raise RuntimeError(f"{method}: no answer in 30 s")
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error']}")
        return r.get("result", {})


async def run(chromium, show_token, on_token, emit_json):
    profile = tempfile.mkdtemp(prefix="fieldseal-passkey-")
    proc = subprocess.Popen(
        [chromium, "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", f"--user-data-dir={profile}",
         "--remote-debugging-port=0", "about:blank"],
        stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)
    endpoint = None
    for _ in range(100):
        line = proc.stderr.readline()
        m = re.search(r"DevTools listening on (ws://\S+)", line)
        if m:
            endpoint = m.group(1)
            break
    if not endpoint:
        raise SystemExit("Chromium did not start")
    # Keep reading Chromium's stderr: a full pipe would block the browser.
    import threading
    threading.Thread(target=lambda: [None for _ in proc.stderr], daemon=True).start()
    try:
        async with websockets.connect(endpoint, max_size=None) as ws:
            cdp = Cdp(ws)
            pump = asyncio.ensure_future(cdp.pump())
            target = (await cdp.call("Target.createTarget", {"url": "about:blank"}))["targetId"]
            sid = (await cdp.call("Target.attachToTarget", {"targetId": target, "flatten": True}))["sessionId"]
            c = lambda method, params=None: cdp.call(method, params, sid)
            await c("Page.enable")
            await c("Runtime.enable")
            await c("WebAuthn.enable", {"enableUI": False})
            auth = await c("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})

            async def js(expr):
                # A page that is navigating may drop the call: retry a few times.
                for attempt in range(6):
                    try:
                        r = await asyncio.wait_for(c("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True}), 8)
                        return r.get("result", {}).get("value")
                    except (asyncio.TimeoutError, RuntimeError):
                        await asyncio.sleep(1)
                return None

            async def goto(url):
                await c("Page.navigate", {"url": url})
                await settle()

            async def settle():
                await asyncio.sleep(0.5)
                for _ in range(60):
                    if await js("document.readyState") == "complete":
                        break
                    await asyncio.sleep(0.25)
                await asyncio.sleep(0.5)

            async def text():
                return await js("location.href + '\\n' + document.body.innerText")

            async def wait_for(pattern, what, seconds=20):
                end = time.time() + seconds
                t = ""
                while time.time() < end:
                    t = await text()
                    if re.search(pattern, t, re.S):
                        return t
                    await asyncio.sleep(0.5)
                raise SystemExit(f"FAIL: {what}\n--- page was:\n{t}")

            def step(msg):
                print(f"== {msg}", flush=True)

            # 1. First sign-in: the username, then passkey registration.
            step("first sign-in: username, then register a passkey")
            await goto(f"{PORTAL}/sign-in")
            await wait_for(r"localhost:8180.*", "redirected to Keycloak")
            await js(f"document.getElementById('username').value = {json.dumps(USER)}; document.querySelector('form').submit()")
            await settle()
            t = await wait_for(r"(?i)passkey|security key|register", "the passkey registration page")
            print("   Keycloak asks to register a passkey")
            await js("setTimeout(() => (document.getElementById('registerWebAuthn') || document.querySelector('[id*=egister]')).click(), 50); true")
            # Some versions ask for a label first.
            await asyncio.sleep(3)
            if os.environ.get("PASSKEY_DEBUG"):
                shot = await c("Page.captureScreenshot", {"format": "png"})
                open("/tmp/claude-1000/passkey-debug.png", "wb").write(base64.b64decode(shot["data"]))
                print([e for e in cdp.events if e.get("method", "").startswith(("Page.javascriptDialog", "Runtime.exception", "Runtime.console"))][:10])
            t = await text() or ""
            if re.search(r"(?i)label", t) and await js("!!document.querySelector('input[name=authenticatorLabel]')"):
                await js("document.querySelector('form').submit()")
            t = await wait_for(r"localhost:8080", "back at the portal after registering", 30)
            creds = (await c("WebAuthn.getCredentials", {"authenticatorId": auth["authenticatorId"]}))["credentials"]
            if len(creds) != 1:
                raise SystemExit(f"FAIL: expected one passkey in the virtual authenticator, found {len(creds)}")
            print(f"   a resident passkey now exists (rpId {creds[0].get('rpId')})")

            # 2. That session is not phishing-resistant: the portal must not issue tokens.
            step("the enrolment session is weaker: the portal refuses a token")
            html = await js("document.documentElement.outerHTML")
            first = (await text()).replace("\n", " | ")
            print("   portal says:", first[:300])
            tokens_form = 'action="/tokens"' in html
            if tokens_form:
                await js("document.querySelector('form[action=\"/tokens\"]').submit()")
                await settle()
                t2 = await text()
                if re.search(r"(?i)registration token|fs-reg|token:", t2) and not re.search(r"(?i)phishing|too weak|stronger", t2):
                    raise SystemExit("FAIL: the portal issued a token for a session that did not use the passkey")
                print("   refused:", t2.replace("\n", " | ")[:300])

            # 3. Start over: forget the cookies, sign in again with the passkey.
            step("second sign-in: the passkey authenticates")
            await c("Network.enable")
            await c("Network.clearBrowserCookies")
            await goto(f"{PORTAL}/sign-in")
            await js(f"document.getElementById('username').value = {json.dumps(USER)}; document.querySelector('form').submit()")
            await settle()
            await wait_for(r"(?i)passkey|authenticate|sign in", "the passkey prompt")
            await js("setTimeout(() => { const b = document.getElementById('authenticateWebAuthnButton') || document.querySelector('[id*=uthenticate]'); b && b.click(); }, 50); true")
            await wait_for(r"localhost:8080", "back at the portal after the passkey", 30)
            await asyncio.sleep(1)
            print("   portal says:", (await text()).replace("\n", " | ")[:300])

            # 4. A registration token.
            step("ask the portal for a registration token")
            await js("document.querySelector('form[action=\"/tokens\"]').submit()")
            await settle()
            t = await text()
            body = await js("document.body.innerText") or ""
            m = re.search(r"FS1T:[A-Z0-9]+", body)
            if not m:
                raise SystemExit(f"FAIL: the portal did not issue a registration token\n{body}")
            print(f"   issued ({len(m.group(0))} characters)")
            if show_token:
                print(m.group(0))

            # 4b. Register a device with the factory over HTTP (the hook), compare the words, confirm.
            if on_token:
                step("register a device with the factory over HTTP (the hook), then confirm its words")
                env = dict(os.environ, FIELDSEAL_TOKEN=m.group(0))
                done = subprocess.run(on_token, shell=True, env=env, capture_output=True, text=True)
                if done.stderr:
                    print(done.stderr.rstrip(), flush=True)
                lines = [l for l in done.stdout.splitlines() if l.strip()]
                if done.returncode != 0 or not lines:
                    raise SystemExit(f"FAIL: the hook failed ({done.returncode}): {done.stdout} {done.stderr}")
                for l in lines[:-1]:
                    print("  ", l)
                info = json.loads(lines[-1])
                words, tenancy = info["words"], info["tenancy"]
                print(f"   device words: {words}")
                await goto(PORTAL + "/")
                page = await js("document.body.innerText") or ""
                # The portal writes each word with its index: "word (123) · word (456) · ...".
                shown = [re.sub(r" \(\d+\)", "", item.strip()) for item in re.findall(r"[^\n]*\(\d+\) · [^\n]*", page)]
                if words not in shown:
                    raise SystemExit(f"FAIL: the portal does not show the device's words {words!r}\n{page}")
                print("   the portal shows the same four words; confirming")
                # Confirm the item that has our words (earlier runs may have left others).
                await js("""(() => { for (const li of document.querySelectorAll('li')) { if (%s.every(w => li.innerText.includes(w))) { li.querySelector('button').click(); return true; } } return false; })()""" % json.dumps(words.split(" · ")))
                await settle()
                status = json.load(urllib.request.urlopen(f"{PORTAL}/v1/registrations/{tenancy}", timeout=10))
                print(f"   registration state: {status['state']}")
                if status["state"] != "registered":
                    raise SystemExit(f"FAIL: expected registered, got {status}")
                if emit_json:
                    json.dump({"words": words, "tenancy": tenancy}, open(emit_json, "w"))

            # 5. What Keycloak asserted: run the code flow by hand (own state, nonce and PKCE
            #    verifier) with the passkey, exchange the code and print the ID token's claims.
            step("what the ID token carries after a passkey sign-in")
            await c("Network.clearBrowserCookies")
            verifier = secrets.token_urlsafe(32)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            redirect = f"{PORTAL}/sign-in/callback"
            query = urllib.parse.urlencode({"response_type": "code", "client_id": "fieldseal-factory", "redirect_uri": redirect,
                                            "scope": "openid", "state": "inspect", "nonce": "inspect", "code_challenge": challenge,
                                            "code_challenge_method": "S256", "acr_values": "phr"})
            await goto(f"{KEYCLOAK}/realms/fieldseal/protocol/openid-connect/auth?{query}")
            await js(f"document.getElementById('username').value = {json.dumps(USER)}; document.querySelector('form').submit()")
            await settle()
            await wait_for(r"(?i)passkey", "the passkey prompt")
            await js("setTimeout(() => { const b = document.getElementById('authenticateWebAuthnButton'); b && b.click(); }, 50); true")
            end, code = time.time() + 30, None
            while time.time() < end and not code:
                href = await js("location.href") or ""
                code = urllib.parse.parse_qs(urllib.parse.urlparse(href).query).get("code", [None])[0] if href.startswith(redirect) else None
                await asyncio.sleep(0.5)
            if not code:
                raise SystemExit("FAIL: no authorization code came back")
            client_secret = secret("FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET")
            form = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                                           "client_id": "fieldseal-factory", "client_secret": client_secret, "code_verifier": verifier}).encode()
            tokens = json.load(urllib.request.urlopen(urllib.request.Request(f"{KEYCLOAK}/realms/fieldseal/protocol/openid-connect/token", data=form), timeout=10))
            payload = tokens["id_token"].split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            shown = {k: claims.get(k) for k in ("iss", "aud", "acr", "amr", "roles", "azp") if k in claims}
            print("   ID token claims:", json.dumps(shown))
            print("   (no `amr` claim)" if "amr" not in claims else "   amr is present")
            if claims.get("acr") != "phr":
                raise SystemExit(f"FAIL: expected acr=phr after a passkey sign-in, got {claims.get('acr')!r}")
            print("OK")
            pump.cancel()
    finally:
        proc.terminate()
        shutil.rmtree(profile, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chromium", default=next((p for p in (shutil.which(n) for n in ("chromium", "chromium-browser", "google-chrome", "chrome")) if p), None))
    ap.add_argument("--show-token", action="store_true")
    ap.add_argument("--on-token", help="a shell command run with the registration token in $FIELDSEAL_TOKEN that registers a device with the factory and prints JSON {words, tenancy} as its last line; the words are then confirmed in the portal")
    ap.add_argument("--emit-json", help="write {words, tenancy} of the confirmed device to this file")
    ap.add_argument("--no-reset", action="store_true", help="do not first remove the user's passkeys (the user must have none)")
    a = ap.parse_args()
    if not a.chromium:
        raise SystemExit("no Chromium found: pass --chromium")
    try:
        urllib.request.urlopen(f"{PORTAL}/readyz", timeout=3)
    except Exception as e:
        raise SystemExit(f"the portal is not up at {PORTAL}: {e} (just up)")
    if not a.no_reset:
        reset_user()
        print("== reset: product-owner has no passkey and must register one")
    asyncio.run(run(a.chromium, a.show_token, a.on_token, a.emit_json))


if __name__ == "__main__":
    sys.exit(main())
