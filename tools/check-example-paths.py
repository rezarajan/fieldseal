#!/usr/bin/env python3
"""Fail if a source file still names the old example layout.

Examples live in survey folders, `examples/surveys/<name>/` (ADR 0041). Source, script, compose,
Nix and configuration files outside `docs/` must not name `examples/instruments/`,
`examples/layouts/`, an example's `<name>.compact.yaml` or `<name>.expanded.yaml`,
`instruments/<survey>.yaml` for a survey in `examples/surveys/`, or an `examples/**/i18n/` path
outside a survey folder. Markdown is not scanned (the docs are updated by hand).

Usage:
    tools/check-example-paths.py [ROOT]    ROOT defaults to the repository root.

Exit 1 with `file:line` for each hit.
"""
import os
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
EXTENSIONS = {".rs", ".sh", ".py", ".yaml", ".yml", ".nix", ".toml", ".json"}
SKIP_DIRS = {".git", ".jj", "target", "docs", ".local-only", ".claude", "node_modules", "result"}


def patterns(root: pathlib.Path) -> list[tuple[re.Pattern[str], str]]:
    surveys = root / "examples" / "surveys"
    names = sorted(p.name for p in surveys.iterdir() if p.is_dir()) if surveys.is_dir() else []
    out = [
        (re.compile(r"examples/instruments/"), "examples/instruments/ no longer exists"),
        (re.compile(r"examples/layouts/"), "examples/layouts/ no longer exists"),
        (re.compile(r"[A-Za-z0-9_-]+\.(?:compact|expanded)\.yaml"), "layouts are examples/surveys/<name>/layouts/<window>.yaml"),
        (re.compile(r"examples/(?!surveys/)[^\s\"']*i18n/"), "catalogues are examples/surveys/<name>/i18n/<lang>.po"),
    ]
    if names:
        alternatives = "|".join(re.escape(n) for n in names)
        out.append((re.compile(rf"instruments/(?:{alternatives})\.yaml"), "an instrument is examples/surveys/<name>/instrument.yaml"))
    return out


def findings(root: pathlib.Path) -> list[str]:
    checks = patterns(root)
    me = pathlib.Path(__file__).resolve()
    out: list[str] = []
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            path = pathlib.Path(here) / name
            if path.resolve() == me or not (path.suffix in EXTENSIONS or name == "justfile"):
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            for n, line in enumerate(lines, start=1):
                for pattern, why in checks:
                    if pattern.search(line):
                        out.append(f"{path.relative_to(root)}:{n}: {why}")
                        break
    return out


def main() -> int:
    root = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else REPO
    found = findings(root)
    for line in found:
        print(line)
    if found:
        print(f"check-example-paths: {len(found)} reference(s) to the old example layout", file=sys.stderr)
        return 1
    print("check-example-paths: no reference to the old example layout")
    return 0


if __name__ == "__main__":
    sys.exit(main())
