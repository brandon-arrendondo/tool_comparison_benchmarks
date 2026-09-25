"""The Infer and Frama-C adapters' parsers, entry-point discovery and
compile-DB handling, on synthetic tool output and a temporary directory. No
tool is invoked and no corpus is read; every path below is invented."""

import json
import tempfile
import unittest
from pathlib import Path

from tcb.tools import frama_c, infer
from tcb.tools.base import Completed

ROOT = Path("/corpus/proj")

INFER_REPORT = [
    {"bug_type": "NULLPTR_DEREFERENCE", "qualifier": "`p` could be null", "severity": "ERROR",
     "line": 12, "column": 5, "file": "src/a.c", "procedure": "f"},
    {"bug_type": "DEAD_STORE", "qualifier": "never used", "severity": "ERROR",
     "line": 3, "column": -1, "file": "/corpus/proj/src/b.c", "procedure": "g"},
    {"bug_type": "MEMORY_LEAK_C", "qualifier": "leak", "severity": "ERROR",
     "line": 7, "column": 2, "file": "/usr/include/x.h", "procedure": "h"},
]

INFER_CAPTURE = """Capturing using compilation database...
Starting translating 4 files
/corpus/proj/src/c.c:2:10: fatal error: 'gen.h' file not found
/corpus/proj/src/c.c:2:10: fatal error: 'gen.h' file not found
"""

FRAMAC_OUT = """[kernel] Parsing /corpus/proj/src/a.c (with preprocessing)
[eva:alarm] /corpus/proj/src/a.c:36: Warning:
  accessing left-value that contains escaping addresses.
  assert ¬\\dangling(&data);
[eva] /corpus/proj/src/a.c:36:
  assertion 'Eva,dangling_pointer' got final status invalid.
[eva:alarm] /corpus/proj/src/a.c:40: Warning: out of bounds read. assert \\valid_read(p + i);
[eva:alarm] /corpus/proj/src/a.c:41: Warning:
  function snprintf_va_1: precondition valid_s: \\valid(s + (0 .. 255));
[eva:alarm] /corpus/proj/include/h.h:4: Warning: signed overflow. assert x + 1 <= 2147483647;
[eva:summary] ====== ANALYSIS SUMMARY ======
"""


class InferTest(unittest.TestCase):
    def test_parse_report(self):
        recs = infer.parse_report(INFER_REPORT, ROOT)
        self.assertEqual([(r["file_path"], r["line"], r["column"], r["check_id"], r["severity"]) for r in recs],
                         [("src/a.c", 12, 5, "NULLPTR_DEREFERENCE", "error"),
                          ("src/b.c", 3, 0, "DEAD_STORE", "error"),
                          ("/usr/include/x.h", 7, 2, "MEMORY_LEAK_C", "error")])
        self.assertEqual(recs[0]["message"], "`p` could be null")

    def test_capture_coverage_counts_a_failed_tu_once(self):
        cov = infer.capture_coverage(INFER_CAPTURE, 4, ROOT)
        self.assertEqual((cov["tus_attempted"], cov["tus_captured"], cov["capture_failures"], cov["partial"]),
                         (4, 3, ["src/c.c"], True))
        self.assertEqual(cov["tus_pct"], 75.0)

    def test_capture_coverage_without_a_count_uses_what_was_handed(self):
        cov = infer.capture_coverage("", 2, ROOT)
        self.assertEqual((cov["tus_captured"], cov["partial"]), (2, False))


class FramaCParseTest(unittest.TestCase):
    def test_alarms_wrapped_and_one_line(self):
        recs = frama_c.parse_output(FRAMAC_OUT, ROOT)
        self.assertEqual([(r["file_path"], r["line"], r["check_id"]) for r in recs],
                         [("src/a.c", 36, "accessing left-value that contains escaping addresses"),
                          ("src/a.c", 40, "out of bounds read"),
                          ("src/a.c", 41, "precondition of snprintf_va_1"),
                          ("include/h.h", 4, "signed overflow")])
        self.assertEqual(recs[0]["message"],
                         "accessing left-value that contains escaping addresses. assert ¬\\dangling(&data)")
        self.assertEqual(recs[1]["message"], "out of bounds read. assert \\valid_read(p + i)")

    def test_only_file(self):
        recs = frama_c.parse_output(FRAMAC_OUT, ROOT, only_file=Path("/corpus/proj/include/h.h"))
        self.assertEqual([r["check_id"] for r in recs], ["signed overflow"])

    def test_nothing_without_alarms(self):
        self.assertEqual(frama_c.parse_output("[eva] done\n", ROOT), [])

    def test_alarm_kind(self):
        self.assertEqual(frama_c.alarm_kind("  out of bounds\n  write "), "out of bounds write")
        self.assertEqual(frama_c.alarm_kind(""), "eva_alarm")
        self.assertEqual(frama_c.alarm_kind("function strncat, behavior complete: precondition 'room_string' "
                                            "got status unknown"), "precondition of strncat")


class FramaCEntriesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_juliet_entries(self):
        f = self.dir / "CWE1_x_01.c"
        f.write_text("void CWE1_x_01_bad()\n{\n}\nstatic void good1()\n{\n}\n"
                     "static void good2() {}\nvoid CWE1_x_01_good()\n{\n good1();\n}\n")
        self.assertEqual(frama_c.juliet_entries(f), ["CWE1_x_01_bad", "CWE1_x_01_good", "good1", "good2"])

    def test_definitions_external_first_declarations_skipped(self):
        f = self.dir / "a.c"
        f.write_text("static int helper(int x)\n{\n  return x;\n}\n"
                     "int api(const char *s);\n"
                     "int api(const char *s)\n{\n  if (s) return helper(1);\n  return 0;\n}\n"
                     "unsigned long\nwrap(void) { return 0; }\n")
        self.assertEqual(frama_c.c_function_definitions(f), ["api", "wrap", "helper"])

    def test_round_robin(self):
        order = frama_c.round_robin({Path("b.c"): ["b1"], Path("a.c"): ["a1", "a2", "a3"], Path("c.c"): []})
        self.assertEqual([e for _, e in order], ["a1", "b1", "a2", "a3"])

    def test_tally_separates_unknown_entries(self):
        def c(rc, expected=None):
            return Completed(["frama-c"], rc, "", "", 0.0, 0.0, 0.0, expected=expected)
        t = frama_c.Adapter._tally([c(0), c(0), c(124, frama_c.ENTRY_TIMEOUT), c(1), c(1, frama_c.UNKNOWN_ENTRY)])
        self.assertEqual(t, {"entries_run": 5, "entries_analyzed": 2, "entries_unknown": 1,
                             "timeouts": 1, "failures": 1})


class MappingFilesTest(unittest.TestCase):
    def test_infer_and_framac_resolve(self):
        from tcb import mapping
        self.assertEqual(mapping.resolve("infer", "NULLPTR_DEREFERENCE")["cwe"], ["CWE-476"])
        self.assertEqual(mapping.resolve("infer", "NO_SUCH_TYPE")["via"], "unmapped")
        self.assertIn("CWE-369", mapping.resolve("frama-c", "division by zero")["cwe"])
        self.assertEqual(mapping.resolve("frama-c", "precondition of fclose")["via"], "unmapped")
        self.assertEqual(mapping.resolve("frama-c", "precondition of memcpy")["cert"], ["ARR38-C"])


if __name__ == "__main__":
    unittest.main()
