"""Scope predicate and tables, on a synthetic bundle written by the bundle
API itself (invented project, invented files)."""

import tempfile
import unittest
from pathlib import Path

from tcb import bundle, scope, tables


class ScopeTest(unittest.TestCase):
    def test_path_aware_globs(self):
        self.assertTrue(scope.matches("src/a.c", "src/*.c"))
        self.assertFalse(scope.matches("src/sub/a.c", "src/*.c"))
        self.assertTrue(scope.matches("src/sub/deep/a.c", "src/**"))
        self.assertTrue(scope.matches("src/sub/a.c", "src/**/a.c"))
        self.assertTrue(scope.matches("a.c", "*.c"))
        self.assertFalse(scope.matches("src/a.c", "*.c"))
        self.assertTrue(scope.matches("src/test_x.h", "src/test_*.h"))

    def test_pinned_projects_use_include_then_exclude(self):
        # libcrc is unrestricted; sqlite includes src/** and excludes src/test*.c
        self.assertTrue(scope.in_scope("libcrc", "anything/at/all.c"))
        self.assertTrue(scope.in_scope("sqlite", "src/main.c"))
        self.assertFalse(scope.in_scope("sqlite", "src/test1.c"))
        self.assertFalse(scope.in_scope("sqlite", "tool/lemon.c"))


class TablesTest(unittest.TestCase):
    def _rw_bundle(self, root, tool, recs):
        b = bundle.Bundle(tool, "0.0", "libcrc", root=root)
        for r in recs:
            b.add_finding(project="libcrc", codebase_commit="c" * 40, severity="warning", message="m", **r)
        b.meta["timing"]["scan_wall_s"] = 1.0
        return b.finish()

    def test_realworld_counts_and_footer(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._rw_bundle(Path(tmp), "cppcheck", [
                dict(file_path="src/a.c", line=1, column=1, check_id="nullPointer"),
                dict(file_path="src/a.c", line=1, column=7, check_id="nullPointer"),   # same key, other column
                dict(file_path="src/b.c", line=2, column=1, check_id="noSuchCheck"),
            ])
            md = tables.realworld_counts([d], None)
            row = [l for l in md.splitlines() if l.startswith("| libcrc")][0]
            cells = [c.strip() for c in row.strip("|").split("|")]
            # findings, in_scope, in_scope_keys, files, check_ids, mapped_%
            self.assertEqual(cells[2:8], ["3", "3", "2", "2", "2", "66.7"])
            self.assertIn("aurora-lint", md)
            self.assertIn("mapping:", md)
            self.assertNotIn("hostname", md)

    def test_juliet_per_cwe_precision_and_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = bundle.Bundle("cppcheck", "0.0", "juliet-CWE476", root=Path(tmp))
            common = dict(project="juliet", codebase_commit="j" * 40, cwe="CWE476", severity="e", message="m", column=1)
            b.add_finding(file_path="CWE476_x/t1.c", line=10, check_id="nullPointer", testcase="t1", section="bad", **common)
            b.add_finding(file_path="CWE476_x/t1.c", line=20, check_id="nullPointer", testcase="t1", section="good", **common)
            b.add_finding(file_path="CWE476_x/t2.c", line=10, check_id="uninitvar", testcase="t2", section="bad", **common)
            d = b.finish()
            (d / "per_cwe.csv").write_text("cwe_dir,cwe,files,files_with_bad_section,status,findings,in_bad_section,in_good_section,unclassified\n"
                                           "CWE476_x,CWE476,4,4,ok,3,2,1,0\n")
            md = tables.juliet_per_cwe([d], None)
            row = [l for l in md.splitlines() if l.startswith("| CWE476")][0]
            cells = [c.strip() for c in row.strip("|").split("|")]
            # in_bad 2, in_good 1, precision_all 66.7; cwe-matched: nullPointer only -> 1 bad, 1 good, 50.0;
            # detected test cases: t1 only -> 1 of 4 = 25.0
            self.assertEqual(cells[6:14], ["2", "1", "66.7", "1", "1", "50.0", "1", "25.0"])


if __name__ == "__main__":
    unittest.main()
