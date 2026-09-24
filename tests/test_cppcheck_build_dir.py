"""cppcheck's build dir: present under `-j` > 1 (else cppcheck 2.10 drops its
whole-program checks), absent at `-j` 1, and always fresh. cppcheck is not
invoked; aurora-lint's command builder is stubbed."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tcb.tools import adapter

BASE = ["cppcheck", "--enable=all", "--std=c11", "--xml", "--xml-version=2", "src"]


class _RR:
    @staticmethod
    def _build_cppcheck_cmd(cfg):
        return list(BASE)


def _argv(jobs: int, workdir: Path):
    ad = adapter("cppcheck")
    with mock.patch("tcb.tools.cppcheck.al_bench.modules", return_value={"realworld_runner": _RR}):
        return ad, ad.realworld_argv({"path": "/corpus"}, workdir, jobs)


class BuildDirTest(unittest.TestCase):
    def test_parallel_run_gets_a_fresh_build_dir(self):
        with tempfile.TemporaryDirectory() as t:
            ad, argv = _argv(12, Path(t))
            flags = [a for a in argv if a.startswith("--cppcheck-build-dir=")]
            self.assertEqual(len(flags), 1)
            build = Path(flags[0].split("=", 1)[1])
            self.assertEqual(build.parent, Path(t))
            self.assertTrue(build.is_dir())
            self.assertEqual(list(build.iterdir()), [])
            self.assertEqual(argv[len(BASE):len(BASE) + 2], ["-j", "12"])
            self.assertIsNotNone(ad.tool_options["cppcheck_build_dir"])

    def test_serial_run_has_no_build_dir(self):
        with tempfile.TemporaryDirectory() as t:
            ad, argv = _argv(1, Path(t))
            self.assertFalse(any(a.startswith("--cppcheck-build-dir") for a in argv))
            self.assertEqual(argv, BASE + ["-j", "1"])
            self.assertIsNone(ad.tool_options["cppcheck_build_dir"])
            self.assertEqual(list(Path(t).iterdir()), [])

    def test_an_existing_build_dir_is_refused_not_reused(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "cppcheck-build").mkdir()
            with self.assertRaises(FileExistsError):
                _argv(12, Path(t))


if __name__ == "__main__":
    unittest.main()
