#!/usr/bin/env python3
"""Enforce Fieldseal's clean-architecture dependency rule (ADR 0028).

Reads architecture.toml and `cargo metadata`, and fails if any workspace crate
depends outward, if an inner crate uses a third-party crate outside the
allow-list, or if inner-layer source reaches for ambient I/O, time or randomness.

Usage: tools/check-architecture.py   (from anywhere in the repository)
"""
import json
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = tomllib.loads((ROOT / "architecture.toml").read_text())
INNER = {"kernel", "contexts"}


def layer_of(name: str) -> str:
    for layer, members in CONFIG["layers"].items():
        for m in members:
            if name == m or (m.endswith("-") and name.startswith(m)):
                return layer
    raise SystemExit(f"architecture: crate {name} is in no layer; add it to architecture.toml")


def main() -> int:
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout)
    workspace = {p["name"]: p for p in meta["packages"]}
    errors: list[str] = []

    for name, pkg in sorted(workspace.items()):
        layer = layer_of(name)
        allowed_layers = set(CONFIG["layer_edges"][layer])
        for dep in pkg["dependencies"]:
            dep_name, kind = dep["name"], dep.get("kind")
            if dep_name in workspace:
                dep_layer = layer_of(dep_name)
                if dep_layer == layer:
                    if layer == "contexts":
                        if dep_name not in CONFIG["context_edges"].get(name, []):
                            errors.append(f"{name} -> {dep_name}: not an edge of the context map")
                    elif layer != "adapters":
                        errors.append(f"{name} -> {dep_name}: {layer} crates must not depend on each other")
                elif dep_layer not in allowed_layers:
                    errors.append(f"{name} ({layer}) -> {dep_name} ({dep_layer}): outward dependency")
            elif layer in INNER and kind is None and dep_name not in CONFIG["inner_external_allow"]["crates"]:
                errors.append(f"{name} ({layer}) uses third-party crate {dep_name}, which is not on the inner allow-list")

        if layer in INNER:
            src = pathlib.Path(pkg["manifest_path"]).parent / "src"
            for path in src.rglob("*.rs"):
                in_tests = False
                for lineno, line in enumerate(path.read_text().splitlines(), 1):
                    code = line.split("//", 1)[0]
                    if re.match(r"\s*#\[cfg\(test\)\]", line):
                        in_tests = True
                    if in_tests:
                        continue
                    for pattern in CONFIG["inner_forbidden_source"]["patterns"]:
                        if pattern in code:
                            rel = path.relative_to(ROOT)
                            errors.append(f"{rel}:{lineno}: uses `{pattern}`; reach it through a port instead")

    if errors:
        print("Architecture check failed (ADR 0028):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"Architecture check passed: {len(workspace)} crates, dependencies point inward.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
