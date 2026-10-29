#!/usr/bin/env python3
"""The survey picker of the browser device (issue #48): one group of two surveys.

An account assigned two surveys for one cohort sees one group on "Your surveys". On the roster the
collector chooses which survey to conduct for the people in it: this test chooses each in turn,
starts a capture for the first person and backs out. The roster the check issues covers the water
survey's consent and not the school-meals survey's, so the meals survey shows the person's
consent as unknown, asks for it on the device before the capture, and the water survey does not.

    picker.py [--collector URL] [--factory URL] [--state DIR]

Run against a running `just web` that has issued `tools/browser-tests/fixtures/picker-a.yaml` and
assigned both example surveys to `picker-a` for the account `collector2` (`tools/dev-web.sh --check
--browser` does). Exit 0 only when every check passes.
"""
import asyncio
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fit = load("phone_fit", "phone-fit.py")
e2e = fit.e2e

WATER, MEALS = "household-water-access", "school-meals-baseline"
SCREEN = "document.getElementById('device').dataset.screen"
PICKS = "[...document.querySelectorAll('#survey-pick .pick')].map((b) => [b.dataset.survey, b.textContent.trim(), b.getAttribute('aria-pressed')])"
FIRST_TAG = "(() => { const t = document.querySelector('#subjects .subject .tag'); return t ? t.textContent.trim() : ''; })()"


async def pressed(device):
    """The survey the picker shows as chosen."""
    return [p[0] for p in await device.ev(PICKS) if p[2] == "true"]


async def choose(device, survey):
    await device.ev(f"document.querySelector('#survey-pick .pick[data-survey={json.dumps(survey)}]').click()")
    await e2e.until_async(lambda: device.ev(f"JSON.stringify({PICKS}.filter((p) => p[2] === 'true').map((p) => p[0])) === {json.dumps(json.dumps([survey]))}"), f"{survey} to be chosen", 20)
    await asyncio.sleep(0.3)


async def back_out(device, survey, title):
    """From a capture, closes it and discards; the roster comes back with the same survey chosen."""
    await device.ev("document.getElementById('discard').click()")
    await device.ev("document.getElementById('discard-yes').click()")
    await fit.screen(device, "roster")
    e2e.check(await pressed(device) == [survey], f"picker: {title} is still the chosen survey after backing out", await pressed(device))
    e2e.check(not await device.text("#capture-error"), f"picker: backing out of {title} leaves no error")


async def main():
    browser = e2e.Browser()
    await browser.start()
    try:
        e2e.section("picker: a group of two surveys (account collector2)")
        portal, device = await fit.register_device(browser, "collector2", WATER)
        await fit.screen(device, "surveys", 120)
        rows = await device.ev("document.querySelectorAll('#survey-list .subject').length")
        e2e.check(rows == 1, "picker: two surveys for one cohort are one group on Your surveys", rows)
        group = await device.text("#survey-list .who b")
        e2e.check(" and " in (group or ""), "picker: the group is titled by both surveys", group)
        await device.ev("document.getElementById('open-survey').click()")
        await fit.screen(device, "roster")

        picks = await device.ev(PICKS)
        names = sorted(p[0] for p in picks)
        e2e.check(names == sorted([WATER, MEALS]), "picker: the roster offers both surveys to choose from", picks)
        e2e.check(len(await pressed(device)) == 1, "picker: exactly one survey is chosen", picks)
        e2e.check(await device.ev("!document.getElementById('survey-pick').hidden"), "picker: the picker is shown")
        await fit.fits(device, "the roster with the survey picker")
        titles = {p[0]: p[1] for p in picks}

        # The water survey: covered by the roster, so a person starts at once.
        await choose(device, WATER)
        e2e.check(await device.text("#capture-error") == "", "picker: choosing a survey clears an earlier error")
        await device.ev("document.getElementById('start-next').click()")
        await fit.screen(device, "capture")
        title = await device.text("#capture-title")
        e2e.check(title.strip() == titles[WATER], "picker: the water survey opens its own form", f"{title!r} vs {titles[WATER]!r}")
        await back_out(device, WATER, titles[WATER])

        # The meals survey: the roster does not cover it, so the person's consent is unknown for it.
        await choose(device, MEALS)
        tag = await device.ev(FIRST_TAG)
        e2e.check(tag == "Consent: unknown", "picker: a roster that does not cover the survey shows the person's consent as unknown", tag)
        await device.ev("document.getElementById('start-next').click()")
        await fit.screen(device, "consent")
        await fit.fits(device, "the consent screen of the second survey")
        await device.ev("document.getElementById('consent-back').click()")
        await fit.screen(device, "roster")
        e2e.check(await pressed(device) == [MEALS], "picker: backing out of consent keeps the chosen survey", await pressed(device))
        await device.ev("document.getElementById('start-next').click()")
        await fit.screen(device, "consent")
        await device.ev("document.querySelector('#consent-basis input').click();document.getElementById('form-consent').requestSubmit()")
        await fit.screen(device, "capture")
        title = await device.text("#capture-title")
        e2e.check(title.strip() == titles[MEALS], "picker: the meals survey opens its own form once consent is recorded", f"{title!r} vs {titles[MEALS]!r}")
        await back_out(device, MEALS, titles[MEALS])

        # Back to the first survey: the person's consent for the meals survey was recorded for that survey only.
        await choose(device, WATER)
        await device.ev("document.getElementById('start-next').click()")
        await fit.screen(device, "capture")
        await back_out(device, WATER, titles[WATER])

        # Switching group and coming back, and a survey that is no longer in the bundle.
        await device.ev("document.getElementById('switch-survey').click()")
        await fit.screen(device, "surveys")
        await device.ev("document.getElementById('open-survey').click()")
        await fit.screen(device, "roster")
        e2e.check(await pressed(device) == [WATER], "picker: the chosen survey is remembered for the group", await pressed(device))
        await device.ev("window.localStorage.setItem(Object.keys(localStorage).find((k) => k.startsWith('fs-active-survey-')), 'gone')")
        await device.ev("document.getElementById('switch-survey').click()")
        await fit.screen(device, "surveys")
        await device.ev("document.getElementById('open-survey').click()")
        await fit.screen(device, "roster")
        e2e.check(len(await pressed(device)) == 1, "picker: a remembered survey that is gone falls back to the group's first", await pressed(device))
        e2e.check(not device.errors, "picker: the page raised no error", device.errors[:3])
        await fit.retire_devices(portal)
    finally:
        browser.proc.kill()
    print("\nRESULT", f"FAILED: {len(e2e.failures)} check(s): " + "; ".join(e2e.failures) if e2e.failures else "the survey picker works for a group of two surveys")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
