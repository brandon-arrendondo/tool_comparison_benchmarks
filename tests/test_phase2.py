"""Parsers and the mapping, on synthetic tool output. No tool is invoked and
no corpus is read; every path below is invented."""

import json
import unittest
from pathlib import Path

from tcb import mapping
from tcb.run import _dedupe
from tcb.tools import clang_tidy, cppcheck
from tcb import MAPPING_DIR

ROOT = Path("/corpus/proj")

CPPCHECK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.13.0"/>
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer dereference: p" verbose="...">
      <location file="/corpus/proj/src/a.c" line="12" column="5"/>
    </error>
    <error id="missingIncludeSystem" severity="information" msg="chatter">
      <location file="/corpus/proj/src/a.c" line="1" column="1"/>
    </error>
    <error id="uninitvar" severity="error" msg="Uninitialized variable: x">
      <location file="/corpus/proj/src/b.c" line="3" column="9"/>
    </error>
    <error id="checkersReport" severity="information" msg="no location"/>
  </errors>
</results>
"""

CLANG_TIDY_TXT = """/corpus/proj/src/a.c:12:5: warning: Dereference of null pointer [clang-analyzer-core.NullDereference]
    *p = 1;
    ^
/corpus/proj/src/a.c:20:3: warning: the value returned by this function should not be disregarded [cert-err33-c]
/corpus/proj/src/a.c:30:1: warning: declaration uses identifier '_x' [cert-dcl37-c,cert-dcl51-cpp]
/corpus/proj/include/h.h:4:1: warning: something in a header [cert-dcl37-c,cert-dcl51-cpp]
/corpus/proj/src/a.c:40:1: error: unknown type name 'foo_t' [clang-diagnostic-error]
9 warnings generated.
"""


class CppcheckParseTest(unittest.TestCase):
    def test_records_and_information_dropped(self):
        recs = cppcheck.parse_xml(CPPCHECK_XML, ROOT)
        self.assertEqual([(r["file_path"], r["line"], r["check_id"]) for r in recs],
                         [("src/a.c", 12, "nullPointer"), ("src/b.c", 3, "uninitvar")])

    def test_only_file_keeps_that_test_case(self):
        recs = cppcheck.parse_xml(CPPCHECK_XML, ROOT, only_file=Path("/corpus/proj/src/b.c"))
        self.assertEqual([r["check_id"] for r in recs], ["uninitvar"])

    def test_garbage_is_empty(self):
        self.assertEqual(cppcheck.parse_xml("", ROOT), [])
        self.assertEqual(cppcheck.parse_xml("<results", ROOT), [])


class ClangTidyParseTest(unittest.TestCase):
    def test_records_errors_dropped_aliases_normalised(self):
        recs = clang_tidy.parse_text(CLANG_TIDY_TXT, ROOT)
        self.assertEqual([(r["file_path"], r["line"], r["column"], r["check_id"]) for r in recs],
                         [("src/a.c", 12, 5, "clang-analyzer-core.NullDereference"),
                          ("src/a.c", 20, 3, "cert-err33-c"),
                          ("src/a.c", 30, 1, "cert-dcl37-c"),
                          ("include/h.h", 4, 1, "cert-dcl37-c")])

    def test_only_file(self):
        recs = clang_tidy.parse_text(CLANG_TIDY_TXT, ROOT, only_file=Path("/corpus/proj/include/h.h"))
        self.assertEqual(len(recs), 1)

    def test_primary_check(self):
        self.assertEqual(clang_tidy.primary_check("cert-dcl37-c,cert-dcl51-cpp"), "cert-dcl37-c")
        self.assertEqual(clang_tidy.primary_check("misc-x,clang-analyzer-core.Y"), "clang-analyzer-core.Y")
        self.assertEqual(clang_tidy.primary_check("misc-x"), "misc-x")


class DedupeTest(unittest.TestCase):
    def test_exact_duplicates_only(self):
        a = dict(file_path="f", line=1, column=1, check_id="c", message="m")
        b = dict(a, column=2)
        out, dropped = _dedupe([a, dict(a), b])
        self.assertEqual((len(out), dropped), (2, 1))


class MappingTest(unittest.TestCase):
    def test_files_parse_and_declare_themselves(self):
        for p in MAPPING_DIR.glob("*.json"):
            d = json.loads(p.read_text())
            self.assertEqual(d["source"], "hand-made", p.name)
            self.assertEqual(d["unmapped_policy"], "counted", p.name)
            for cid, e in d["entries"].items():
                self.assertIn("cert", e, f"{p.name}:{cid}")
                self.assertIn("cwe", e, f"{p.name}:{cid}")
                for r in e["cert"]:
                    self.assertRegex(r, r"^[A-Z]{3}\d{2}-C$", f"{p.name}:{cid}")
                for c in e["cwe"]:
                    self.assertRegex(c, r"^CWE-\d+$", f"{p.name}:{cid}")

    def test_entry_pattern_and_unmapped(self):
        self.assertEqual(mapping.resolve("cppcheck", "nullPointer")["cert"], ["EXP34-C"])
        r = mapping.resolve("clang-tidy", "cert-err33-c")
        self.assertEqual((r["cert"], r["via"]), (["ERR33-C"], "pattern"))
        self.assertEqual(mapping.resolve("cppcheck", "noSuchCheck")["via"], "unmapped")
        self.assertEqual(mapping.resolve("aurora-lint", "EXP34-C")["cert"], ["EXP34-C"])

    def test_coverage_counts_findings_and_ids(self):
        cov = mapping.coverage("cppcheck", ["nullPointer", "nullPointer", "zzz"])
        self.assertEqual(cov["findings"], {"entry": 2, "pattern": 0, "unmapped": 1})
        self.assertEqual(cov["check_ids"], {"entry": 1, "pattern": 0, "unmapped": 1})
        self.assertEqual(cov["unmapped_top"], [("zzz", 1)])


if __name__ == "__main__":
    unittest.main()
