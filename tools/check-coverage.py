#!/usr/bin/env python3
"""Report which spec requirements have tests (spec README, "Traceability").

Every test names the requirement IDs it covers; a requirement without a test is a gap.
This tool finds the defined IDs in docs/reference/spec/*.md, finds the IDs that tests name,
and reports the difference. It reports only: CI fails on it only when asked to with
--fail-under-must.

Defined IDs are `**PREFIX-NNN**` (optional letter suffix) at the start of a list item or of a
table row. A requirement's level is the first RFC 2119 keyword in its text; a table row that
has a "Level" column uses that column (Required and Invariant mean MUST, Recommended and
Strongly recommended mean SHOULD, Optional means MAY). A requirement whose text contains
"*Withdrawn" is withdrawn and not counted. A requirement whose text starts with "(Proposed, ADR"
(a new requirement of an ADR that is not yet approved) is pending and not counted either, until
the marker is removed on approval.

Covered IDs are named in test sources under the scanned roots (default: crates, runtimes,
tests) in either of two ways:
  - a test function whose name starts with or contains `prefix_NNN` (lowercase, optional
    letter), for example `fn ins_126_repeat_expands_in_list_order` after `#[test]`, or
    `def test_ins_126_...` in Python, or a Kotlin function after `@Test`;
  - a comment `// covers: INS-126, WIRE-002` (`#` in Python), where `INS-050..INS-053` or
    `INS-050-INS-053` names a range.

Usage:
  tools/check-coverage.py                       summary per spec
  tools/check-coverage.py --json                the same, for machines
  tools/check-coverage.py --list-uncovered INS  the uncovered requirements of one prefix
  tools/check-coverage.py --fail-under-must INS=80 WIRE=100
                                                exit 1 if a prefix's MUST coverage is lower
  tools/check-coverage.py --baseline tools/coverage-baseline.toml
                                                the same, with the thresholds read from a TOML file
                                                ([must] table of PREFIX = PERCENT); the ratchet
"""
import argparse
import json
import os
import pathlib
import re
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = ROOT / "docs" / "reference" / "spec"
DEFAULT_ROOTS = ["crates", "runtimes", "tests"]
SOURCE_SUFFIXES = {".rs", ".py", ".kt", ".kts", ".java"}
SKIP_DIRS = {"target", ".git", "node_modules", "build", "dist", ".gradle", "__pycache__", ".venv"}

ID = r"([A-Z]{2,5})-(\d{3})([a-z]?)"
LIST_DEF = re.compile(r"^\s*[-*]\s+\*\*" + ID + r"\*\*(.*)$")
TABLE_DEF = re.compile(r"^\|\s*\*\*" + ID + r"\*\*\s*\|(.*)$")
PENDING = re.compile(r"\s*\(Proposed, ADR \d{4}\)")
KEYWORD = re.compile(r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|MAY)\b")
LEVEL_WORDS = [
    ("strongly recommended", "SHOULD"), ("recommended", "SHOULD"), ("required", "MUST"),
    ("invariant", "MUST"), ("optional", "MAY"),
]
MUST_LEVELS = {"MUST", "MUST NOT", "SHALL", "SHALL NOT"}

COVERS = re.compile(r"(?:^|\s)(?://|#|\*|/\*)\s*covers:\s*(.*)$")
ID_OR_RANGE = re.compile(ID + r"(?:\s*(?:\.\.|–|—|-)\s*" + ID + r")?")
TEST_ATTR = re.compile(r"#\[(?:[\w:]*::)?(?:test|rstest|test_case)\b|@Test\b")
FN_DEF = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:fn|def|fun)\s+`?([A-Za-z_][\w ]*)`?")
NAME_ID = re.compile(r"(?<![a-z0-9])([a-z]{2,5})_(\d{3})([a-z])?(?![a-z0-9])")


def level_from_column(cell: str) -> str | None:
    text = cell.strip().lower()
    for word, level in LEVEL_WORDS:
        if text.startswith(word):
            return level
    return None


def level_from_text(text: str) -> str:
    m = KEYWORD.search(text)
    if m:
        return m.group(1)
    if re.search(r"\*Could\b|\bCould,", text):
        return "COULD"
    return "UNSPECIFIED"


def parse_specs() -> dict[str, dict]:
    """Returns {id: {id, prefix, spec, line, level, withdrawn, text}} for every defined ID."""
    defined: dict[str, dict] = {}
    for path in sorted(SPEC_DIR.glob("*.md")):
        lines = path.read_text().splitlines()
        level_col = None  # index of the "Level" cell in the current table
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("|"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if cells and cells[0] == "ID":
                    level_col = next((n for n, c in enumerate(cells) if c.lower() == "level"), None)
            else:
                level_col = None
            m = LIST_DEF.match(line)
            table = False
            if not m:
                m = TABLE_DEF.match(line)
                table = m is not None
            if m:
                prefix, number, suffix, rest = m.groups()
                text = rest.split("|")[0] if table else rest
                if not table:  # a list item continues on indented lines until a blank line
                    j = i + 1
                    while j < len(lines) and lines[j].strip() and lines[j].startswith(" ") \
                            and not re.match(r"^\s*[-*]\s", lines[j]):
                        text += " " + lines[j].strip()
                        j += 1
                level = None
                if table and level_col is not None:
                    cells = [c.strip() for c in line.strip().strip("|").split("|")]
                    if level_col < len(cells):
                        level = level_from_column(cells[level_col])
                if level is None:
                    level = level_from_text(text)
                rid = f"{prefix}-{number}{suffix}"
                if rid in defined:
                    print(f"warning: {rid} is defined twice ({defined[rid]['spec']}:{defined[rid]['line']} and "
                          f"{path.name}:{i + 1}); using the first", file=sys.stderr)
                else:
                    defined[rid] = {
                        "id": rid, "prefix": prefix, "spec": path.stem, "line": i + 1, "level": level,
                        "withdrawn": "*Withdrawn" in text or bool(PENDING.match(text)), "text": re.sub(r"\s+", " ", text).strip(" |"),
                    }
            i += 1
    return defined


def expand(match: re.Match) -> list[str]:
    p1, n1, s1, p2, n2, s2 = match.groups()
    if p2 is None:
        return [f"{p1}-{n1}{s1}"]
    if p2 != p1 or int(n2) < int(n1):
        return [f"{p1}-{n1}{s1}", f"{p2}-{n2}{s2}"]
    return [f"{p1}-{n:03d}" for n in range(int(n1), int(n2) + 1)] + ([f"{p1}-{n1}{s1}"] if s1 else [])


def has_test_attribute(lines: list[str], n: int) -> bool:
    """Whether the function on line n is preceded, directly, by a test attribute."""
    k = n - 1
    while k >= 0 and re.match(r"\s*(#\[|@|//)", lines[k]):
        if TEST_ATTR.search(lines[k]):
            return True
        k -= 1
    return False


def scan_sources(roots: list[pathlib.Path], prefixes: set[str]) -> dict[str, set[str]]:
    """Returns {id: {file:line, ...}} for every ID that a test names."""
    found: dict[str, set[str]] = defaultdict(set)
    lowered = {p.lower() for p in prefixes}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = pathlib.Path(dirpath, name)
                if path.suffix not in SOURCE_SUFFIXES:
                    continue
                try:
                    lines = path.read_text().splitlines()
                except (UnicodeDecodeError, OSError):
                    continue
                rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
                for n, line in enumerate(lines):
                    where = f"{rel}:{n + 1}"
                    m = COVERS.search(line)
                    if m:
                        for im in ID_OR_RANGE.finditer(m.group(1)):
                            for rid in expand(im):
                                found[rid].add(where)
                    fm = FN_DEF.match(line)
                    if not fm:
                        continue
                    is_test = (path.suffix == ".py" and fm.group(1).startswith("test")) or has_test_attribute(lines, n)
                    if not is_test:
                        continue
                    for nm in NAME_ID.finditer(fm.group(1).replace(" ", "_").lower()):
                        if nm.group(1) in lowered:
                            found[f"{nm.group(1).upper()}-{nm.group(2)}{nm.group(3) or ''}"].add(where)
    return found


def percent(covered: int, total: int) -> float:
    return 100.0 if total == 0 else 100.0 * covered / total


def summarise(defined: dict[str, dict], found: dict[str, set[str]]) -> dict:
    specs: dict[str, dict] = {}
    for req in defined.values():
        s = specs.setdefault(req["prefix"], {
            "spec": req["spec"], "prefix": req["prefix"], "defined": 0, "withdrawn": 0, "must": 0,
            "covered": 0, "covered_must": 0, "uncovered_must": 0, "uncovered": [], "uncovered_must_ids": [],
        })
        if req["withdrawn"]:
            s["withdrawn"] += 1
            continue
        s["defined"] += 1
        must = req["level"] in MUST_LEVELS
        covered = req["id"] in found
        s["must"] += must
        s["covered"] += covered
        s["covered_must"] += covered and must
        if not covered:
            s["uncovered"].append(req["id"])
            if must:
                s["uncovered_must"] += 1
                s["uncovered_must_ids"].append(req["id"])
    for s in specs.values():
        s["must_percent"] = round(percent(s["covered_must"], s["must"]), 1)
        s["percent"] = round(percent(s["covered"], s["defined"]), 1)
    totals = {k: sum(s[k] for s in specs.values()) for k in
              ("defined", "withdrawn", "must", "covered", "covered_must", "uncovered_must")}
    totals["must_percent"] = round(percent(totals["covered_must"], totals["must"]), 1)
    unknown = {rid: sorted(w) for rid, w in found.items() if rid not in defined}
    withdrawn_named = {rid: sorted(w) for rid, w in found.items() if rid in defined and defined[rid]["withdrawn"]}
    return {"specs": dict(sorted(specs.items(), key=lambda kv: kv[1]["spec"])), "totals": totals,
            "unknown_ids_named": unknown, "withdrawn_ids_named": withdrawn_named}


def print_table(report: dict) -> None:
    head = ("spec", "prefix", "defined", "MUST", "covered", "uncovered MUST", "MUST %")
    rows = [head]
    for s in report["specs"].values():
        rows.append((s["spec"], s["prefix"], str(s["defined"]), str(s["must"]), str(s["covered"]),
                     str(s["uncovered_must"]), f"{s['must_percent']:.1f}"))
    t = report["totals"]
    rows.append(("total", "", str(t["defined"]), str(t["must"]), str(t["covered"]),
                 str(t["uncovered_must"]), f"{t['must_percent']:.1f}"))
    widths = [max(len(r[i]) for r in rows) for i in range(len(head))]
    for n, r in enumerate(rows):
        print("  ".join(c.ljust(w) if i < 2 else c.rjust(w) for i, (c, w) in enumerate(zip(r, widths))))
        if n == 0 or n == len(rows) - 2:
            print("  ".join("-" * w for w in widths))
    if report["unknown_ids_named"]:
        print("\nTests name IDs that no spec defines:")
        for rid, where in sorted(report["unknown_ids_named"].items()):
            print(f"  {rid}: {', '.join(where[:3])}")
    if report["withdrawn_ids_named"]:
        print("\nTests name withdrawn IDs:")
        for rid, where in sorted(report["withdrawn_ids_named"].items()):
            print(f"  {rid}: {', '.join(where[:3])}")


def parse_thresholds(items: list[str]) -> dict[str, float]:
    out = {}
    for item in items:
        prefix, sep, value = item.partition("=")
        try:
            out[prefix.strip().upper()] = float(value)
        except ValueError:
            raise SystemExit(f"coverage: --fail-under-must wants PREFIX=PERCENT, got {item!r}") from None
        if not sep:
            raise SystemExit(f"coverage: --fail-under-must wants PREFIX=PERCENT, got {item!r}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Report spec requirements that no test names.")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--list-uncovered", metavar="PREFIX", action="append", default=[],
                    help="list the uncovered requirements of a prefix (repeatable)")
    ap.add_argument("--fail-under-must", metavar="PREFIX=PERCENT", nargs="+", default=[],
                    help="exit 1 if a prefix's MUST coverage is below PERCENT (PREFIX may be ALL)")
    ap.add_argument("--baseline", metavar="FILE", help="TOML file with a [must] table of PREFIX = PERCENT thresholds")
    ap.add_argument("--root", action="append", default=None,
                    help=f"directory to scan for tests, relative to the repository (default: {' '.join(DEFAULT_ROOTS)})")
    args = ap.parse_args()

    defined = parse_specs()
    if not defined:
        raise SystemExit(f"coverage: no requirement IDs found under {SPEC_DIR}")
    roots = [ROOT / r for r in (args.root or DEFAULT_ROOTS) if (ROOT / r).is_dir()]
    found = scan_sources(roots, {r["prefix"] for r in defined.values()})
    report = summarise(defined, found)

    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        print()
    elif args.list_uncovered:
        for prefix in args.list_uncovered:
            prefix = prefix.upper()
            if prefix not in report["specs"]:
                raise SystemExit(f"coverage: no spec has prefix {prefix}; known: {', '.join(sorted(report['specs']))}")
            for rid in report["specs"][prefix]["uncovered"]:
                r = defined[rid]
                snippet = r["text"][:90] + ("..." if len(r["text"]) > 90 else "")
                print(f"{rid:<10} {r['level']:<11} {r['spec']}.md:{r['line']}  {snippet}")
    else:
        print_table(report)
        print("\nReport only: pass --fail-under-must PREFIX=PERCENT to make a threshold fail.")

    failures = []
    thresholds = {}
    if args.baseline:
        import tomllib
        with open(args.baseline, "rb") as f:
            thresholds.update({k.upper(): float(v) for k, v in tomllib.load(f).get("must", {}).items()})
    thresholds.update(parse_thresholds(args.fail_under_must))
    for prefix, limit in thresholds.items():
        got = report["totals"]["must_percent"] if prefix == "ALL" else (
            report["specs"][prefix]["must_percent"] if prefix in report["specs"] else None)
        if got is None:
            raise SystemExit(f"coverage: no spec has prefix {prefix}")
        if got < limit:
            failures.append(f"{prefix}: MUST coverage {got:.1f}% is below {limit:g}%")
    if failures:
        print("\nCoverage below threshold:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
