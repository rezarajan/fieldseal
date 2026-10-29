#!/usr/bin/env python3
"""Fail if an example declares a placeholder copyright.

Every YAML file under examples/ is read line by line. The check fails, naming the file and
line, when a file declares the licence `LicenseRef-to-be-confirmed`, or a copyright notice
that says the holder is "to be confirmed". A published example must say who holds the
copyright and under which licence it is offered.

Usage:
    tools/check-example-licences.py [ROOT]    ROOT defaults to the repository root;
                                              the check reads ROOT/examples.
    tools/check-example-licences.py --self-test
        Plants the placeholder in a temporary copy of examples/ and expects the check to fail.
"""
import pathlib
import re
import shutil
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent

LICENCE = re.compile(r"LicenseRef-to-be-confirmed", re.IGNORECASE)
NOTICE = re.compile(r"\bnotice\b.*to be confirmed", re.IGNORECASE)


def findings(root: pathlib.Path) -> list[str]:
    examples = root / "examples"
    if not examples.is_dir():
        raise SystemExit(f"check-example-licences: {examples} is not a directory")
    out: list[str] = []
    files = sorted(p for p in examples.rglob("*") if p.is_file() and p.suffix in (".yaml", ".yml"))
    for path in files:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            rel = path.relative_to(root)
            if LICENCE.search(line):
                out.append(f"{rel}:{n}: copyright licence `LicenseRef-to-be-confirmed` is a placeholder")
            elif NOTICE.search(line):
                out.append(f"{rel}:{n}: copyright notice says the holder is \"to be confirmed\"")
    return out


def check(root: pathlib.Path) -> int:
    bad = findings(root)
    if bad:
        print("check-example-licences: an example declares a placeholder copyright:", file=sys.stderr)
        for b in bad:
            print(f"  {b}", file=sys.stderr)
        print("Name the copyright holder and licence, or remove the example.", file=sys.stderr)
        return 1
    return 0


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        shutil.copytree(REPO / "examples", root / "examples")
        victim = next((root / "examples").rglob("*.yaml"))
        planted = victim.read_text(encoding="utf-8") + "\ncopyright: {notice: Holder to be confirmed, licence: LicenseRef-to-be-confirmed}\n"
        victim.write_text(planted, encoding="utf-8")
        if not findings(root):
            print("check-example-licences: self-test failed: a planted placeholder was not found", file=sys.stderr)
            return 1
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) > 2:
        raise SystemExit(__doc__)
    return check(pathlib.Path(argv[1]).resolve() if len(argv) == 2 else REPO)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
