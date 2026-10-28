#!/usr/bin/env python3
"""Tests for tools/check-coverage.py. Run: python3 tools/check_coverage_test.py"""
import importlib.util
import pathlib
import tempfile
import textwrap
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_coverage", HERE / "check-coverage.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

SPEC = textwrap.dedent("""\
    # Demo

    - **DEM-001** A thing MUST work.
    - **DEM-002** *Withdrawn: gone.*
    - **DEM-003** It SHOULD be fast, and MUST NOT leak.
    - **DEM-004a** Continued over
      two lines, so the keyword MAY be late.
    - **DEM-005** *Could, schema 1.1:* a thing MAY happen.
    - **DEM-006** No keyword at all.

    | ID | Requirement | Level |
    |---|---|---|
    | **DEM-010** | Keys MUST be safe. | Required |
    | **DEM-011** | Evidence SHOULD bind. | Optional; policy decides |
    | **DEM-012** | Keys MUST rotate. | Recommended |
    """)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)
        (self.dir / "demo.md").write_text(SPEC)
        cc.SPEC_DIR = self.dir
        self.defined = cc.parse_specs()

    def test_proposed_requirements_are_pending_not_counted(self):
        (self.dir / "demo.md").write_text(
            "- **DEM-020** (Proposed, ADR 0099) A new thing MUST work.\n"
            "- **DEM-021** An amended thing MUST work *(Amendment proposed, ADR 0099: tighter)*.\n")
        d = cc.parse_specs()
        self.assertTrue(d["DEM-020"]["withdrawn"])
        self.assertFalse(d["DEM-021"]["withdrawn"])

    def test_levels_and_withdrawn(self):
        d = self.defined
        self.assertEqual(d["DEM-001"]["level"], "MUST")
        self.assertTrue(d["DEM-002"]["withdrawn"])
        self.assertEqual(d["DEM-003"]["level"], "SHOULD")  # the first keyword wins
        self.assertEqual(d["DEM-004a"]["level"], "MAY")
        self.assertEqual(d["DEM-005"]["level"], "MAY")
        self.assertEqual(d["DEM-006"]["level"], "UNSPECIFIED")
        self.assertEqual(d["DEM-010"]["level"], "MUST")
        self.assertEqual(d["DEM-011"]["level"], "MAY")  # the Level column wins
        self.assertEqual(d["DEM-012"]["level"], "SHOULD")
        self.assertEqual(d["DEM-010"]["text"], "Keys MUST be safe.")

    def test_ranges(self):
        m = cc.ID_OR_RANGE.search("DEM-001..DEM-003, DEM-010")
        self.assertEqual(cc.expand(m), ["DEM-001", "DEM-002", "DEM-003"])

    def scan(self, name, source):
        src = self.dir / "src"
        src.mkdir(exist_ok=True)
        (src / name).write_text(textwrap.dedent(source))
        return cc.scan_sources([src], {"DEM"})

    def test_rust_names_and_comments(self):
        found = self.scan("a.rs", """\
            #[test]
            fn dem_001_works() {}

            // covers: DEM-003, DEM-004a
            #[test]
            fn something_else() {}

            fn dem_010_not_a_test() {}

            #[test]
            fn dem_004a_suffix_then_name() {}
            """)
        self.assertEqual(set(found), {"DEM-001", "DEM-003", "DEM-004a"})

    def test_python_and_kotlin(self):
        found = self.scan("t.py", """\
            def test_dem_012_rotates():
                pass

            def helper_dem_010():
                pass
            """)
        self.assertEqual(set(found), {"DEM-012"})
        found = self.scan("t.kt", """\
            @Test
            fun `dem_010 keys are safe`() {}
            """)
        self.assertIn("DEM-010", found)

    def test_summary_excludes_withdrawn_and_counts_must(self):
        found = {"DEM-001": {"x"}, "DEM-011": {"x"}, "DEM-999": {"y"}}
        report = cc.summarise(self.defined, found)
        s = report["specs"]["DEM"]
        self.assertEqual((s["defined"], s["withdrawn"]), (8, 1))
        self.assertEqual(s["must"], 2)  # DEM-001 and DEM-010; DEM-003 and DEM-012 are SHOULD
        self.assertEqual(s["covered_must"], 1)
        self.assertEqual(s["uncovered_must_ids"], ["DEM-010"])
        self.assertIn("DEM-999", report["unknown_ids_named"])


if __name__ == "__main__":
    unittest.main()
